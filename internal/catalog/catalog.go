// Package catalog loads the approved-module catalog from cloud-pravaha-modules.
//
// The catalog is the only source of modules a stack may use: every entry is a
// public OpenTofu registry module pinned to exact versions, plus the provider
// versions those modules may pull in. Nothing outside the catalog can be run.
package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Registry is the only module and provider registry the platform trusts.
const Registry = "registry.opentofu.org"

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	sourceRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[a-z0-9]{1,32}$`)
	provRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[a-z0-9][a-z0-9-]{0,63}$`)
	semverRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	inputRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
	inputType = map[string]bool{
		"string": true, "number": true, "bool": true,
		"list(string)": true, "list(number)": true,
		"map(string)": true, "map(bool)": true, "json": true,
	}
)

type Provider struct {
	Source  string `json:"source"`  // e.g. hashicorp/aws
	Version string `json:"version"` // exact pin
	Cloud   string `json:"cloud"`   // aws | gcp | azure | ""
}

type Dependency struct {
	Source   string   `json:"source"`
	Versions []string `json:"versions"`
}

type Input struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Required    bool     `json:"required,omitempty"`
	Description string   `json:"description,omitempty"`
	Default     any      `json:"default,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	ItemPattern string   `json:"item_pattern,omitempty"`
	Allowed     []any    `json:"allowed,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	MaxItems    int      `json:"max_items,omitempty"`

	pattern     *regexp.Regexp
	itemPattern *regexp.Regexp
}

func (i *Input) PatternRe() *regexp.Regexp     { return i.pattern }
func (i *Input) ItemPatternRe() *regexp.Regexp { return i.itemPattern }

type Module struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	Description  string         `json:"description"`
	Source       string         `json:"source"` // namespace/name/provider
	Versions     []string       `json:"versions"`
	Cloud        string         `json:"cloud"`
	Providers    []string       `json:"providers"`
	Dependencies []Dependency   `json:"dependencies,omitempty"`
	Inputs       []*Input       `json:"inputs"`
	Enforced     map[string]any `json:"enforced,omitempty"`
	Outputs      []string       `json:"outputs"`
}

func (m *Module) Input(name string) *Input {
	for _, in := range m.Inputs {
		if in.Name == name {
			return in
		}
	}
	return nil
}

func (m *Module) HasVersion(v string) bool { return contains(m.Versions, v) }

func (m *Module) HasOutput(o string) bool { return contains(m.Outputs, o) }

// LatestVersion is the last listed version; catalogs list versions oldest first.
func (m *Module) LatestVersion() string { return m.Versions[len(m.Versions)-1] }

type Catalog struct {
	Modules   []*Module  `json:"modules"`
	Providers []Provider `json:"providers"`

	byID     map[string]*Module
	bySource map[string]*Module
	provider map[string]Provider
}

func (c *Catalog) Module(id string) *Module { return c.byID[id] }

func (c *Catalog) ModuleBySource(src string) *Module { return c.bySource[strings.ToLower(src)] }

func (c *Catalog) Provider(src string) (Provider, bool) {
	p, ok := c.provider[strings.ToLower(src)]
	return p, ok
}

// ModuleVersionAllowed reports whether a registry module address (with or without
// the registry host) at a version is approved, either as a catalog module or as a
// declared dependency of one.
func (c *Catalog) ModuleVersionAllowed(source, version string) bool {
	source = strings.TrimPrefix(strings.ToLower(source), Registry+"/")
	if m := c.bySource[source]; m != nil && m.HasVersion(version) {
		return true
	}
	for _, m := range c.Modules {
		for _, d := range m.Dependencies {
			if strings.EqualFold(d.Source, source) && contains(d.Versions, version) {
				return true
			}
		}
	}
	return false
}

// New builds a catalog from already-decoded parts (for example, the copy a
// runner receives with a job) and validates it exactly as Load does.
func New(mods []*Module, provs []Provider) (*Catalog, error) {
	c := &Catalog{Modules: mods, Providers: provs}
	if err := c.index(); err != nil {
		return nil, err
	}
	return c, nil
}

// Catalog layout, segregated by cloud provider:
//
//	providers/<cloud>.json      providers for that cloud (exact pins)
//	modules/<cloud>/<name>.json modules for that cloud
//
// <cloud> is aws, gcp, azure, or "common" for modules and providers that need
// no cloud credentials. The folder is the single source of truth for a
// module's cloud, and a module may only use its own cloud's providers plus
// common ones, so an AWS module can never pull in a GCP provider.
const CommonFolder = "common"

// Clouds lists the supported cloud folders (besides common).
var Clouds = []string{"aws", "gcp", "azure"}

func folderCloud(folder string) (string, bool) {
	if folder == CommonFolder {
		return "", true
	}
	for _, c := range Clouds {
		if folder == c {
			return c, true
		}
	}
	return "", false
}

// Load reads a catalog directory laid out as described above and validates it.
func Load(dir string) (*Catalog, error) {
	var errs []error
	if _, err := os.Stat(filepath.Join(dir, "providers.json")); err == nil {
		errs = append(errs, errors.New("providers.json is the old flat layout; split it into providers/<cloud>.json"))
	}
	if flat, _ := filepath.Glob(filepath.Join(dir, "modules", "*.json")); len(flat) > 0 {
		errs = append(errs, fmt.Errorf("modules must live in modules/<cloud>/, found %s", filepath.Base(flat[0])))
	}
	c := &Catalog{}
	pfiles, _ := filepath.Glob(filepath.Join(dir, "providers", "*.json"))
	sort.Strings(pfiles)
	if len(pfiles) == 0 {
		errs = append(errs, fmt.Errorf("%s: no providers/<cloud>.json files", dir))
	}
	for _, f := range pfiles {
		cloud, ok := folderCloud(strings.TrimSuffix(filepath.Base(f), ".json"))
		if !ok {
			errs = append(errs, fmt.Errorf("%s: unknown cloud; use one of %s or %s", f, strings.Join(Clouds, ", "), CommonFolder))
			continue
		}
		var pf struct {
			Registry  string     `json:"registry"`
			Providers []Provider `json:"providers"`
		}
		if err := readJSON(f, &pf); err != nil {
			errs = append(errs, err)
			continue
		}
		if pf.Registry != Registry {
			errs = append(errs, fmt.Errorf("%s: registry must be %q", f, Registry))
		}
		for _, p := range pf.Providers {
			if p.Cloud != "" {
				errs = append(errs, fmt.Errorf("%s: provider %s must not set cloud; the file name decides it", f, p.Source))
			}
			p.Cloud = cloud
			c.Providers = append(c.Providers, p)
		}
	}
	entries, err := os.ReadDir(filepath.Join(dir, "modules"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		cloud, ok := folderCloud(e.Name())
		if !ok {
			errs = append(errs, fmt.Errorf("modules/%s: unknown cloud folder; use one of %s or %s", e.Name(), strings.Join(Clouds, ", "), CommonFolder))
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, "modules", e.Name(), "*.json"))
		sort.Strings(files)
		for _, f := range files {
			var m Module
			if err := readJSON(f, &m); err != nil {
				errs = append(errs, err)
				continue
			}
			if m.Cloud != "" {
				errs = append(errs, fmt.Errorf("%s: must not set cloud; the folder decides it", f))
			}
			m.Cloud = cloud
			c.Modules = append(c.Modules, &m)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if err := c.index(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Catalog) index() error {
	c.byID = map[string]*Module{}
	c.bySource = map[string]*Module{}
	c.provider = map[string]Provider{}
	var errs []error
	for _, p := range c.Providers {
		if !provRe.MatchString(p.Source) || !semverRe.MatchString(p.Version) {
			errs = append(errs, fmt.Errorf("provider %q: source must be namespace/type and version an exact x.y.z pin", p.Source))
		}
		if _, dup := c.provider[strings.ToLower(p.Source)]; dup {
			errs = append(errs, fmt.Errorf("provider %q is listed more than once", p.Source))
		}
		if _, ok := folderCloud(cloudFolder(p.Cloud)); !ok {
			errs = append(errs, fmt.Errorf("provider %q: unknown cloud %q", p.Source, p.Cloud))
		}
		c.provider[strings.ToLower(p.Source)] = p
	}
	for _, m := range c.Modules {
		where := "module " + m.ID
		if !idRe.MatchString(m.ID) {
			errs = append(errs, fmt.Errorf("%s: invalid id", where))
		}
		if c.byID[m.ID] != nil {
			errs = append(errs, fmt.Errorf("%s: duplicate id", where))
		}
		if !sourceRe.MatchString(m.Source) {
			errs = append(errs, fmt.Errorf("%s: source %q must be a public registry address namespace/name/provider", where, m.Source))
		}
		if len(m.Versions) == 0 {
			errs = append(errs, fmt.Errorf("%s: at least one pinned version required", where))
		}
		for _, v := range m.Versions {
			if !semverRe.MatchString(v) {
				errs = append(errs, fmt.Errorf("%s: version %q must be an exact x.y.z pin", where, v))
			}
		}
		for _, d := range m.Dependencies {
			if !sourceRe.MatchString(d.Source) || len(d.Versions) == 0 {
				errs = append(errs, fmt.Errorf("%s: dependency %q needs a registry source and pinned versions", where, d.Source))
			}
			for _, v := range d.Versions {
				if !semverRe.MatchString(v) {
					errs = append(errs, fmt.Errorf("%s: dependency version %q must be exact", where, v))
				}
			}
		}
		if _, ok := folderCloud(cloudFolder(m.Cloud)); !ok {
			errs = append(errs, fmt.Errorf("%s: unknown cloud %q", where, m.Cloud))
		}
		for _, p := range m.Providers {
			pv, ok := c.provider[strings.ToLower(p)]
			switch {
			case !ok:
				errs = append(errs, fmt.Errorf("%s: provider %q is not allowlisted in providers/", where, p))
			case pv.Cloud != "" && pv.Cloud != m.Cloud:
				errs = append(errs, fmt.Errorf("%s: a %s module cannot use the %s provider %q", where, cloudFolder(m.Cloud), pv.Cloud, p))
			}
		}
		seen := map[string]bool{}
		for _, in := range m.Inputs {
			if !inputRe.MatchString(in.Name) || !inputType[in.Type] || seen[in.Name] {
				errs = append(errs, fmt.Errorf("%s: input %q has an invalid name, type %q or is duplicated", where, in.Name, in.Type))
			}
			if _, enforced := m.Enforced[in.Name]; enforced {
				errs = append(errs, fmt.Errorf("%s: input %q is both user-settable and enforced", where, in.Name))
			}
			seen[in.Name] = true
			var err error
			if in.Pattern != "" {
				if in.pattern, err = regexp.Compile(in.Pattern); err != nil {
					errs = append(errs, fmt.Errorf("%s: input %q pattern: %w", where, in.Name, err))
				}
			}
			if in.ItemPattern != "" {
				if in.itemPattern, err = regexp.Compile(in.ItemPattern); err != nil {
					errs = append(errs, fmt.Errorf("%s: input %q item_pattern: %w", where, in.Name, err))
				}
			}
		}
		c.byID[m.ID] = m
		c.bySource[strings.ToLower(m.Source)] = m
	}
	return errors.Join(errs...)
}

func cloudFolder(cloud string) string {
	if cloud == "" {
		return CommonFolder
	}
	return cloud
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
