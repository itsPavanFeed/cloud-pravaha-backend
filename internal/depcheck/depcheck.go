// Package depcheck verifies a working directory after `tofu init`.
//
// Spec validation only sees the modules a user asked for. Those modules can pull
// in nested modules and providers of their own, so after init the runner checks
// what was actually downloaded:
//
//   - every module came from registry.opentofu.org at an approved version, or is a
//     local subdirectory inside an approved module package;
//   - every provider in the dependency lock file is allowlisted at its pinned version;
//   - no loaded module contains provisioners or the external data source, which
//     would run arbitrary commands on the runner.
package depcheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

var (
	lockProviderRe = regexp.MustCompile(`(?m)^provider\s+"([^"]+)"\s*\{`)
	lockVersionRe  = regexp.MustCompile(`(?m)^\s*version\s*=\s*"([^"]+)"`)
	// Code that executes commands on the runner host.
	execPatterns = []*regexp.Regexp{
		regexp.MustCompile(`provisioner\s+"(local-exec|remote-exec|file)"`),
		regexp.MustCompile(`"provisioner"\s*:`),
		regexp.MustCompile(`data\s+"external"`),
		regexp.MustCompile(`"external"\s*:\s*\{`),
		regexp.MustCompile(`hashicorp/external`),
	}
)

type modulesManifest struct {
	Modules []struct {
		Key     string `json:"Key"`
		Source  string `json:"Source"`
		Version string `json:"Version"`
		Dir     string `json:"Dir"`
	} `json:"Modules"`
}

// Check inspects workdir after init. It returns every violation found.
func Check(workdir string, cat *catalog.Catalog) error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	root, err := filepath.EvalSymlinks(workdir)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(filepath.Join(root, ".terraform", "modules", "modules.json"))
	if err != nil {
		return fmt.Errorf("reading module manifest: %w", err)
	}
	var mf modulesManifest
	if err := json.Unmarshal(b, &mf); err != nil {
		return fmt.Errorf("parsing module manifest: %w", err)
	}

	// Registry packages, keyed by manifest key, so local submodules can be
	// checked to stay inside the package they came from.
	packages := map[string]string{}
	var loadedDirs []string
	for _, m := range mf.Modules {
		if m.Key == "" {
			continue
		}
		dir, err := resolveInside(root, m.Dir)
		if err != nil {
			add("module %s: %v", m.Key, err)
			continue
		}
		switch {
		case strings.HasPrefix(m.Source, catalog.Registry+"/"):
			addr := strings.TrimPrefix(m.Source, catalog.Registry+"/")
			pkg := dir
			if i := strings.Index(addr, "//"); i >= 0 {
				// A submodule of a registry package: the package root is the boundary
				// for its local references (siblings like ../../modules/x are fine).
				sub := filepath.FromSlash(addr[i+2:])
				addr = addr[:i]
				if strings.HasSuffix(dir, string(filepath.Separator)+sub) {
					pkg = strings.TrimSuffix(dir, string(filepath.Separator)+sub)
				}
			}
			if !cat.ModuleVersionAllowed(addr, m.Version) {
				add("module %s: %s@%s is not an approved registry module version", m.Key, addr, m.Version)
				continue
			}
			packages[m.Key] = pkg
		case strings.HasPrefix(m.Source, "./") || strings.HasPrefix(m.Source, "../"):
			pkg := owningPackage(m.Key, packages)
			if pkg == "" || !within(dir, pkg) {
				add("module %s: local source %q escapes its approved registry package", m.Key, m.Source)
				continue
			}
		default:
			add("module %s: source %q is not allowed (only %s modules are permitted)", m.Key, m.Source, catalog.Registry)
			continue
		}
		loadedDirs = append(loadedDirs, dir)
	}

	for _, dir := range loadedDirs {
		if err := scanForExec(dir); err != nil {
			add("%v", err)
		}
	}

	lock, err := os.ReadFile(filepath.Join(root, ".terraform.lock.hcl"))
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("reading dependency lock file: %w", err))...)
	}
	blocks := lockProviderRe.FindAllStringSubmatchIndex(string(lock), -1)
	for i, loc := range blocks {
		addr := string(lock[loc[2]:loc[3]])
		end := len(lock)
		if i+1 < len(blocks) {
			end = blocks[i+1][0]
		}
		vm := lockVersionRe.FindSubmatch(lock[loc[1]:end])
		if !strings.HasPrefix(addr, catalog.Registry+"/") {
			add("provider %s: not from %s", addr, catalog.Registry)
			continue
		}
		src := strings.TrimPrefix(addr, catalog.Registry+"/")
		p, ok := cat.Provider(src)
		if !ok {
			add("provider %s is not allowlisted", src)
			continue
		}
		if vm == nil || string(vm[1]) != p.Version {
			add("provider %s: locked version does not match the pinned %s", src, p.Version)
		}
	}
	return errors.Join(errs...)
}

// scanForExec reads only the files OpenTofu loads for a module: *.tf and
// *.tf.json directly inside its directory (examples/ and tests/ are never loaded).
func scanForExec(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !(strings.HasSuffix(n, ".tf") || strings.HasSuffix(n, ".tf.json") || strings.HasSuffix(n, ".tofu") || strings.HasSuffix(n, ".tofu.json")) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return err
		}
		src := stripComments(string(b))
		for _, re := range execPatterns {
			if re.MatchString(src) {
				return fmt.Errorf("%s: contains command execution (%s), which is not allowed", filepath.Join(filepath.Base(dir), n), re.String())
			}
		}
	}
	return nil
}

var commentRe = regexp.MustCompile(`(?m)(^\s*(#|//).*$)|(/\*(?s:.*?)\*/)`)

func stripComments(s string) string { return commentRe.ReplaceAllString(s, "") }

func owningPackage(key string, packages map[string]string) string {
	for k := key; k != ""; {
		if dir, ok := packages[k]; ok {
			return dir
		}
		i := strings.LastIndex(k, ".")
		if i < 0 {
			break
		}
		k = k[:i]
	}
	return ""
}

func resolveInside(root, rel string) (string, error) {
	p, err := filepath.EvalSymlinks(filepath.Join(root, rel))
	if err != nil {
		return "", err
	}
	if !within(p, filepath.Join(root, ".terraform", "modules")) {
		return "", fmt.Errorf("directory %q is outside the module cache", rel)
	}
	return p, nil
}

func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel)
}
