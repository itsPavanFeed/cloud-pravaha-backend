package release

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

// Fetcher downloads one registry module package at an exact version and
// returns its files (relative to the package root) and where they came from.
type Fetcher interface {
	Fetch(ctx context.Context, source, version string) (files map[string][]byte, origin string, err error)
}

// Registry fetches packages the way OpenTofu does: it asks the registry
// where a version lives and downloads that. Only GitHub locations pinned to
// a ref are followed, as an archive of exactly that commit.
type Registry struct {
	HC      *http.Client
	Base    string                               // default https://registry.opentofu.org
	Archive func(owner, repo, ref string) string // default codeload.github.com
}

var (
	ghPathRe = regexp.MustCompile(`^/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(\.git)?(//(.+))?$`)
	refRe    = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,128}$`)
)

const (
	maxArchive = 100 << 20
	maxFile    = 4 << 20
	maxFiles   = 20000
)

func (r *Registry) client() *http.Client {
	if r.HC != nil {
		return r.HC
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

func (r *Registry) Fetch(ctx context.Context, source, version string) (map[string][]byte, string, error) {
	base := r.Base
	if base == "" {
		base = "https://" + catalog.Registry
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/v1/modules/"+catalog.BaseSource(source)+"/"+url.PathEscape(version)+"/download", nil)
	req.Header.Set("Accept", "application/json")
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	loc := resp.Header.Get("X-Terraform-Get")
	if resp.StatusCode == http.StatusOK && loc == "" {
		var b struct {
			Location string `json:"location"`
		}
		json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&b)
		loc = b.Location
	}
	if resp.StatusCode >= 300 || loc == "" {
		return nil, "", fmt.Errorf("the registry has no download for %s %s (%s)", source, version, resp.Status)
	}
	owner, repo, ref, sub, err := parseLocation(loc)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", source, version, err)
	}
	archive := "https://codeload.github.com/" + owner + "/" + repo + "/tar.gz/" + ref
	if r.Archive != nil {
		archive = r.Archive(owner, repo, ref)
	}
	files, err := r.download(ctx, archive, sub)
	if err != nil {
		return nil, "", fmt.Errorf("%s %s: %w", source, version, err)
	}
	return files, "github.com/" + owner + "/" + repo + "@" + ref, nil
}

// parseLocation accepts git::https://github.com/<owner>/<repo>[//sub]?ref=<ref>
// (and the same without git::), nothing else.
func parseLocation(loc string) (owner, repo, ref, sub string, err error) {
	u, err := url.Parse(strings.TrimPrefix(loc, "git::"))
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil {
		return "", "", "", "", fmt.Errorf("the registry points to %q; only GitHub sources are accepted", loc)
	}
	m := ghPathRe.FindStringSubmatch(u.Path)
	ref = u.Query().Get("ref")
	if m == nil || !refRe.MatchString(ref) || strings.Contains(ref, "..") {
		return "", "", "", "", fmt.Errorf("the registry location %q is not a GitHub repository pinned to a ref", loc)
	}
	sub = strings.Trim(m[5], "/")
	if strings.Contains(sub, "..") {
		return "", "", "", "", errors.New("the registry location escapes its repository")
	}
	return m[1], m[2], ref, sub, nil
}

func (r *Registry) download(ctx context.Context, archive, sub string) (map[string][]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, archive, nil)
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading the archive returned %s", resp.Status)
	}
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, maxArchive))
	if err != nil {
		return nil, fmt.Errorf("reading the archive: %w", err)
	}
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue // symlinks and devices are never vendored
		}
		name := path.Clean(h.Name)
		i := strings.Index(name, "/")
		if i < 0 || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			continue
		}
		rel := name[i+1:]
		if sub != "" {
			var ok bool
			if rel, ok = strings.CutPrefix(rel, sub+"/"); !ok {
				continue
			}
		}
		if !wanted(rel) || h.Size > maxFile {
			continue
		}
		if len(files) >= maxFiles {
			return nil, errors.New("the module package has too many files")
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile))
		if err != nil {
			return nil, err
		}
		files[rel] = b
	}
	if len(files) == 0 {
		return nil, errors.New("the archive holds no module files")
	}
	return files, nil
}

// wanted keeps what a module needs at plan time and drops what it never
// loads: examples, tests, CI and documentation assets.
func wanted(rel string) bool {
	for _, d := range []string{"examples/", "example/", "test/", "tests/", "docs/", ".github/", ".circleci/", ".git/", "wrappers/"} {
		if strings.HasPrefix(rel, d) || strings.Contains(rel, "/"+d) {
			return false
		}
	}
	switch strings.ToLower(path.Ext(rel)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".mp4", ".zip", ".gz", ".tgz", ".jar", ".exe", ".bin", ".so", ".dll":
		return false
	}
	return true
}
