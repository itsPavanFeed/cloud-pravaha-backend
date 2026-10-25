package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
)

// Tiers an environment can declare (see package risk).
var Tiers = []string{"prod", "nonprod"}

// Defaults is one tenant's defaults for one kind, from
// tenants/<tenant>/defaults/<Kind>.yaml in the modules repository:
//
//	apiVersion: pravaha/v1
//	kind: Defaults
//	target: S3Bucket
//	version: 5.17.0          # optional: the version contracts get unless they pin one
//	spec:                    # every environment of the tenant
//	  force_destroy: false
//	tiers:                   # optional, per environment tier
//	  prod:
//	    force_destroy: false
//
// Values are checked against the kind's inputs exactly like contract values,
// and can never touch an enforced baseline.
type Defaults struct {
	APIVersion string                                `json:"apiVersion"`
	Kind       string                                `json:"kind"`
	Target     string                                `json:"target"`
	Version    string                                `json:"version,omitempty"`
	Spec       map[string]json.RawMessage            `json:"spec,omitempty"`
	Tiers      map[string]map[string]json.RawMessage `json:"tiers,omitempty"`
	File       string                                `json:"file,omitempty"`
}

// Overlay holds one tenant's defaults, keyed by kind.
type Overlay struct {
	Tenant string               `json:"tenant"`
	Kinds  map[string]*Defaults `json:"kinds"`
}

// For returns the defaults for a kind, or nil.
func (o *Overlay) For(kind string) *Defaults {
	if o == nil {
		return nil
	}
	return o.Kinds[kind]
}

// APIVersion is the only version of the platform's YAML documents.
const APIVersion = "pravaha/v1"

// LoadOverlay reads <dir>/defaults/*.yaml for one tenant. A missing directory is
// an empty overlay. Each file must target a kind of cat; values are validated
// separately (spec.ValidateOverlay), because that needs the input checker.
func LoadOverlay(fsys fs.FS, dir, tenant string, cat *Catalog) (*Overlay, error) {
	ov := &Overlay{Tenant: tenant, Kinds: map[string]*Defaults{}}
	var errs []error
	for _, f := range dataFiles(fsys, path.Join(dir, "defaults")) {
		var d Defaults
		if err := readData(fsys, f, &d); err != nil {
			errs = append(errs, err)
			continue
		}
		d.File = f
		switch {
		case d.APIVersion != APIVersion:
			errs = append(errs, fmt.Errorf("%s: apiVersion must be %s", f, APIVersion))
		case d.Kind != "Defaults":
			errs = append(errs, fmt.Errorf("%s: kind must be Defaults", f))
		case cat.Kind(d.Target) == nil:
			errs = append(errs, fmt.Errorf("%s: target %q is not a kind in the catalog", f, d.Target))
		case stem(f) != d.Target:
			errs = append(errs, fmt.Errorf("%s: the file must be named after its target (%s.yaml)", f, d.Target))
		case ov.Kinds[d.Target] != nil:
			errs = append(errs, fmt.Errorf("%s: defaults for %s are defined twice", f, d.Target))
		default:
			m := cat.Kind(d.Target)
			if d.Version != "" && !m.HasVersion(d.Version) {
				errs = append(errs, fmt.Errorf("%s: version %s of %s is not in the catalog", f, d.Version, d.Target))
			}
			for t := range d.Tiers {
				if !contains(Tiers, t) {
					errs = append(errs, fmt.Errorf("%s: unknown tier %q (use %v)", f, t, Tiers))
				}
			}
			ov.Kinds[d.Target] = &d
		}
	}
	return ov, errors.Join(errs...)
}

// Kinds lists the kinds with defaults, sorted.
func (o *Overlay) KindNames() []string {
	if o == nil {
		return nil
	}
	out := make([]string, 0, len(o.Kinds))
	for k := range o.Kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
