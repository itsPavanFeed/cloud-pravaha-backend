// Package release turns what tenants keep in Git into versioned, verified
// releases the platform deploys: module releases (kinds, the tenant's
// defaults and every module package vendored from the registry) and policy
// releases (Rego policy sets with their tests).
//
// A build validates everything, writes one deterministic bundle and names it
// by its SHA-256. Bundles are immutable, so they can be cached anywhere by
// checksum; runs consume modules only from a deployed bundle and never
// download modules from the internet.
package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

const (
	ManifestFile = "manifest.json"
	maxBundle    = 128 << 20
	maxEntry     = 8 << 20
	maxEntries   = 50000
)

// Kinds of release.
const (
	Modules  = "modules"
	Policies = "policies"
)

// Manifest describes a release. It is stored next to the bundle, so the
// platform can deploy a release (catalog, defaults, policy sets) without
// reading the bundle itself; runs read the bundle only for vendored modules.
type Manifest struct {
	Kind     string    `json:"kind"`
	Revision string    `json:"revision"` // Git commit the release was built from
	Tenant   string    `json:"tenant"`
	BuiltAt  time.Time `json:"built_at"`

	// Module releases.
	Catalog  *CatalogData       `json:"catalog,omitempty"`
	Defaults *catalog.Overlay   `json:"defaults,omitempty"`
	Packages map[string]Package `json:"packages,omitempty"` // "<registry package>@<version>"
	// Modules maps every catalog module and dependency, as "<source>@<version>",
	// to its directory in the bundle (submodules included).
	Modules map[string]string `json:"modules,omitempty"`

	// Policy releases.
	Policies []PolicySet `json:"policies,omitempty"`
}

type CatalogData struct {
	Modules   []*catalog.Module  `json:"modules"`
	Providers []catalog.Provider `json:"providers"`
}

// Package is one vendored registry module package.
type Package struct {
	Dir    string `json:"dir"`    // vendor/<namespace>/<name>/<provider>/<version>
	Origin string `json:"origin"` // where the registry pointed, pinned to a commit
	SHA256 string `json:"sha256"` // over the vendored files
	Files  int    `json:"files"`
	Bytes  int64  `json:"bytes"`
	// Deps are the packages its module calls load (by package key), so a run
	// receives exactly the closure of what it uses.
	Deps []string `json:"deps,omitempty"`
}

// Closure returns the package directories (with checksums) a module
// directory loads: its own package plus every dependency, transitively.
func (m *Manifest) Closure(dir string) map[string]string {
	byDir := map[string]string{}
	for k, p := range m.Packages {
		byDir[p.Dir] = k
	}
	out := map[string]string{}
	var walk func(key string)
	walk = func(key string) {
		p, ok := m.Packages[key]
		if !ok || out[p.Dir] != "" {
			return
		}
		out[p.Dir] = p.SHA256
		for _, d := range p.Deps {
			walk(d)
		}
	}
	walk(byDir[PackageRootOf(dir)])
	return out
}

// PackageRootOf is the package directory (vendor/<ns>/<name>/<provider>/<version>)
// holding a module directory.
func PackageRootOf(dir string) string {
	parts := strings.Split(dir, "/")
	if len(parts) < 5 {
		return dir
	}
	return strings.Join(parts[:5], "/")
}

// PolicySet is one Rego policy set of a policy release.
type PolicySet struct {
	Name        string `json:"name"`
	Scope       string `json:"scope"` // tenant | entity:<slug> | bu:<slug>
	Level       string `json:"level"` // hard | advisory
	Description string `json:"description,omitempty"`
	Module      string `json:"module"`
	File        string `json:"file"`
	Tests       int    `json:"tests"`
}

// Check is one validation step of a build, shown to people as is.
type Check struct {
	Name   string   `json:"name"`
	OK     bool     `json:"ok"`
	Detail string   `json:"detail,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// Result is a build's outcome. Bundle is nil when any check failed.
type Result struct {
	Manifest *Manifest `json:"manifest"`
	Checks   []Check   `json:"checks"`
	Bundle   []byte    `json:"-"`
	SHA256   string    `json:"sha256,omitempty"`
}

// OK reports whether every check passed.
func (r *Result) OK() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

func (r *Result) check(name string, errs []error, detail string) bool {
	c := Check{Name: name, OK: len(errs) == 0, Detail: detail}
	for _, e := range errs {
		for _, line := range strings.Split(e.Error(), "\n") {
			if line = strings.TrimSpace(line); line != "" && len(c.Errors) < 200 {
				c.Errors = append(c.Errors, line)
			}
		}
	}
	r.Checks = append(r.Checks, c)
	return c.OK
}

// Pack writes a deterministic gzipped tarball: sorted entries, no times,
// owners or modes beyond 0644, manifest first.
func Pack(m *Manifest, files map[string][]byte) ([]byte, string, error) {
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	put := func(name string, b []byte) error {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := put(ManifestFile, mj); err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := put(n, files[n]); err != nil {
			return nil, "", err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, "", err
	}
	if err := gz.Close(); err != nil {
		return nil, "", err
	}
	if buf.Len() > maxBundle {
		return nil, "", fmt.Errorf("the bundle is %d MiB; the limit is %d MiB", buf.Len()>>20, maxBundle>>20)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:]), nil
}

// Unpack verifies a bundle against its expected checksum and calls keep for
// each file (after the manifest) whose name it wants; nothing else is read
// into memory. Names are cleaned and must stay relative.
func Unpack(bundle []byte, wantSHA string, keep func(name string) bool, each func(name string, b []byte) error) (*Manifest, error) {
	sum := sha256.Sum256(bundle)
	if hex.EncodeToString(sum[:]) != wantSHA {
		return nil, errors.New("bundle checksum does not match the release")
	}
	gz, err := gzip.NewReader(bytes.NewReader(bundle))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	var m *Manifest
	for n := 0; ; n++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if n > maxEntries {
			return nil, errors.New("bundle has too many files")
		}
		name := path.Clean(h.Name)
		if h.Typeflag != tar.TypeReg || name != h.Name || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "../") || name == ".." || h.Size > maxEntry {
			return nil, fmt.Errorf("bundle entry %q is not allowed", h.Name)
		}
		if n == 0 {
			if name != ManifestFile {
				return nil, errors.New("bundle does not start with its manifest")
			}
			var mm Manifest
			if err := json.NewDecoder(io.LimitReader(tr, maxEntry)).Decode(&mm); err != nil {
				return nil, fmt.Errorf("bundle manifest: %w", err)
			}
			m = &mm
			continue
		}
		if keep != nil && !keep(name) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxEntry))
		if err != nil {
			return nil, err
		}
		if err := each(name, b); err != nil {
			return nil, err
		}
	}
	if m == nil {
		return nil, errors.New("bundle has no manifest")
	}
	return m, nil
}
