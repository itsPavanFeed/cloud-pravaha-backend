// Package contracts reads a tenant's contracts repository: one JSON file per
// stack ({"name","environment","spec"}) under a folder of a Git branch.
//
// Sources are pull-based: the tenant plane asks the Git host for the branch's
// current commit and downloads a snapshot when it changes. Nothing on the Git
// side calls into the tenant plane.
package contracts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	maxArchive   = 50 << 20
	maxFiles     = 2000
	maxFileBytes = 1 << 20
)

// Config is a tenant's contracts repository. The token is stored separately, sealed.
type Config struct {
	Provider string `json:"provider"`          // github | gitlab | local
	Repo     string `json:"repo"`              // owner/name (GitHub), group/project (GitLab), directory (local)
	Branch   string `json:"branch"`            // e.g. main
	Path     string `json:"path"`              // folder holding contracts, e.g. stacks
	APIURL   string `json:"api_url,omitempty"` // GitHub Enterprise / self-hosted GitLab API base
	Auth     string `json:"auth,omitempty"`    // token (default) | github_app
	// Layout of the folder: "flat" (<path>/<stack>.json, the environment in the
	// file) or "nested" (<path>/<entity>/<environment>/<bu>/<stack>.json).
	Layout           string `json:"layout,omitempty"`
	PollSeconds      int    `json:"poll_seconds"` // >= 30
	AutoPlan         bool   `json:"auto_plan"`    // queue a plan for every new or changed contract
	AutoApplyLowRisk bool   `json:"auto_apply_low_risk"`
	Enabled          bool   `json:"enabled"`
}

var (
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}(/[A-Za-z0-9_.-]{1,100}){1,5}$`)
	branchRe = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,200}$`)
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9._/-]{0,200}$`)
)

// Validate checks a configuration. allowLocal permits the development-only
// local-directory source.
func (c *Config) Validate(allowLocal bool) error {
	var errs []error
	switch c.Provider {
	case "github", "gitlab":
		if !repoRe.MatchString(c.Repo) {
			errs = append(errs, errors.New("repo must look like owner/name"))
		}
		if c.APIURL != "" {
			if u, err := url.Parse(c.APIURL); err != nil || u.Scheme != "https" || u.Host == "" {
				errs = append(errs, errors.New("api_url must be an https URL"))
			}
		}
	case "local":
		if !allowLocal {
			errs = append(errs, errors.New(`the "local" provider is for development only (PRAVAHA_ALLOW_LOCAL_CONTRACTS=1)`))
		} else if !filepath.IsAbs(c.Repo) {
			errs = append(errs, errors.New("local repo must be an absolute directory"))
		}
	default:
		errs = append(errs, errors.New(`provider must be "github" or "gitlab"`))
	}
	switch c.Layout {
	case "", "flat", "nested":
	default:
		errs = append(errs, errors.New(`layout must be "flat" or "nested"`))
	}
	switch c.Auth {
	case "", "token":
	case "github_app":
		if c.Provider != "github" {
			errs = append(errs, errors.New(`auth "github_app" works only with the github provider`))
		}
	default:
		errs = append(errs, errors.New(`auth must be "token" or "github_app"`))
	}
	if !branchRe.MatchString(c.Branch) || strings.Contains(c.Branch, "..") {
		errs = append(errs, errors.New("branch is invalid"))
	}
	if !pathRe.MatchString(c.Path) || strings.Contains(c.Path, "..") {
		errs = append(errs, errors.New("path is invalid"))
	}
	if c.PollSeconds < 30 || c.PollSeconds > 86400 {
		errs = append(errs, errors.New("poll_seconds must be between 30 and 86400"))
	}
	return errors.Join(errs...)
}

// Contract is one stack definition from the repository.
type Contract struct {
	File        string          `json:"file"`
	Name        string          `json:"name"`
	Environment string          `json:"environment"`
	Spec        json.RawMessage `json:"spec"`
	BU          string          `json:"bu,omitempty"` // the owning business unit (from the folder in the nested layout)
	Entity      string          `json:"-"`            // nested layout: the entity (product) folder
}

// Source fetches contracts from a Git host.
type Source interface {
	Revision(ctx context.Context) (string, error)
	Files(ctx context.Context, rev string) (map[string][]byte, error) // repo-relative path -> content
}

// New builds the source for a configuration.
func New(c Config, token string, hc *http.Client) (Source, error) {
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	switch c.Provider {
	case "github":
		api := c.APIURL
		if api == "" {
			api = "https://api.github.com"
		}
		return &github{api: strings.TrimRight(api, "/"), repo: c.Repo, branch: c.Branch, token: token, hc: hc}, nil
	case "gitlab":
		api := c.APIURL
		if api == "" {
			api = "https://gitlab.com/api/v4"
		}
		return &gitlab{api: strings.TrimRight(api, "/"), repo: c.Repo, branch: c.Branch, token: token, hc: hc}, nil
	case "local":
		return &local{dir: c.Repo}, nil
	}
	return nil, fmt.Errorf("unknown provider %q", c.Provider)
}

// Parse extracts contracts from the files under dir. Each file is named after
// its stack (<name>.json); problems are returned per file so one bad contract
// does not block the others.
func Parse(files map[string][]byte, dir string) ([]Contract, map[string]string) {
	return ParseLayout(files, dir, "flat")
}

// ParseLayout is Parse for a folder layout. With "nested", contracts live at
// <dir>/<entity>/<environment>/<bu>/<stack>.json: the entity's (product's)
// environments are shared by its business units. A file that also names the
// environment or BU must agree with its folders.
func ParseLayout(files map[string][]byte, dir, layout string) ([]Contract, map[string]string) {
	dir = strings.Trim(dir, "/")
	var out []Contract
	problems := map[string]string{}
	names := make([]string, 0, len(files))
	for f := range files {
		names = append(names, f)
	}
	sort.Strings(names)
	for _, f := range names {
		if path.Ext(f) != ".json" {
			continue
		}
		var entity, bu, env string
		if layout == "nested" {
			rel, inside := f, true
			if dir != "" {
				rel, inside = strings.CutPrefix(f, dir+"/")
			}
			if !inside {
				continue
			}
			parts := strings.Split(rel, "/")
			if len(parts) != 4 {
				problems[f] = "with the nested layout, contracts live at " + path.Join(dir, "<entity>/<environment>/<bu>/<stack>.json")
				continue
			}
			entity, env, bu = parts[0], parts[1], parts[2]
		} else if path.Dir(f) != firstNonEmpty(dir, ".") {
			continue
		}
		var c Contract
		dec := json.NewDecoder(bytes.NewReader(files[f]))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			problems[f] = "invalid contract: " + err.Error()
			continue
		}
		if stem := strings.TrimSuffix(path.Base(f), ".json"); c.Name != stem {
			problems[f] = fmt.Sprintf("contract name %q must match its file name %q", c.Name, stem)
			continue
		}
		if layout == "nested" {
			if c.Environment == "" {
				c.Environment = env
			} else if c.Environment != env {
				problems[f] = fmt.Sprintf("the file names environment %q but sits in folder %q", c.Environment, env)
				continue
			}
			if c.BU != "" && c.BU != bu {
				problems[f] = fmt.Sprintf("the file names business unit %q but sits in folder %q", c.BU, bu)
				continue
			}
			c.Entity, c.BU = entity, bu
		}
		c.File = f
		out = append(out, c)
	}
	return out, problems
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- GitHub ----

type github struct {
	api, repo, branch, token string
	hc                       *http.Client
}

func (g *github) req(ctx context.Context, u, accept string) (*http.Response, error) {
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	r.Header.Set("Accept", accept)
	r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.token != "" {
		r.Header.Set("Authorization", "Bearer "+g.token)
	}
	resp, err := g.hc.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GitHub returned %s for %s", resp.Status, strings.SplitN(u, "?", 2)[0])
	}
	return resp, nil
}

func (g *github) Revision(ctx context.Context) (string, error) {
	resp, err := g.req(ctx, g.api+"/repos/"+g.repo+"/commits/"+url.PathEscape(g.branch), "application/vnd.github.sha")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
	return checkSHA(string(b))
}

func (g *github) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	resp, err := g.req(ctx, g.api+"/repos/"+g.repo+"/tarball/"+rev, "application/vnd.github+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return untar(resp.Body)
}

// ---- GitLab ----

type gitlab struct {
	api, repo, branch, token string
	hc                       *http.Client
}

func (g *gitlab) req(ctx context.Context, u string) (*http.Response, error) {
	r, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if g.token != "" {
		r.Header.Set("PRIVATE-TOKEN", g.token)
	}
	resp, err := g.hc.Do(r)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GitLab returned %s for %s", resp.Status, strings.SplitN(u, "?", 2)[0])
	}
	return resp, nil
}

func (g *gitlab) project() string { return g.api + "/projects/" + url.PathEscape(g.repo) }

func (g *gitlab) Revision(ctx context.Context) (string, error) {
	resp, err := g.req(ctx, g.project()+"/repository/branches/"+url.PathEscape(g.branch))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var b struct {
		Commit struct{ ID string } `json:"commit"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&b); err != nil {
		return "", err
	}
	return checkSHA(b.Commit.ID)
}

func (g *gitlab) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	resp, err := g.req(ctx, g.project()+"/repository/archive.tar.gz?sha="+url.QueryEscape(rev))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return untar(resp.Body)
}

// ---- local directory (development and tests only) ----

type local struct{ dir string }

func (l *local) Files(ctx context.Context, rev string) (map[string][]byte, error) {
	files := map[string][]byte{}
	err := filepath.WalkDir(l.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || len(files) >= maxFiles {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, _ := filepath.Rel(l.dir, p)
		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes {
			return err
		}
		b, err := os.ReadFile(p)
		files[filepath.ToSlash(rel)] = b
		return err
	})
	return files, err
}

// Revision is a content hash, standing in for a commit SHA.
func (l *local) Revision(ctx context.Context) (string, error) {
	files, err := l.Files(ctx, "")
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))[:40], nil
}

// ---- helpers ----

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

func checkSHA(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !shaRe.MatchString(s) {
		return "", errors.New("Git host returned an invalid commit SHA")
	}
	return s, nil
}

// untar reads a gzipped tarball whose entries share one top-level directory
// (as GitHub and GitLab produce) and returns regular files relative to it.
func untar(r io.Reader) (map[string][]byte, error) {
	gz, err := gzip.NewReader(io.LimitReader(r, maxArchive))
	if err != nil {
		return nil, fmt.Errorf("reading archive: %w", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return files, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		i := strings.Index(name, "/")
		if i < 0 || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			continue
		}
		rel := name[i+1:]
		if h.Size > maxFileBytes {
			continue
		}
		if len(files) >= maxFiles {
			return nil, errors.New("contracts repository has too many files")
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFileBytes))
		if err != nil {
			return nil, err
		}
		files[rel] = b
	}
}
