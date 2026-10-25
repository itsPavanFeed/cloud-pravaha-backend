// Package spec defines stack specs and cloud integrations, validates them
// against the catalog, and generates the OpenTofu configuration.
//
// Users never write HCL. A stack spec lists resources by kind with literal
// input values (only the ones that differ from the defaults); the platform
// resolves defaults and generates main.tf itself, so the only code that runs is
// pinned public registry modules plus configuration the platform controls.
package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/redact"
)

const (
	maxModules     = 20
	maxStringLen   = 1024
	maxListItems   = 50
	maxMapEntries  = 50
	maxJSONDepth   = 6
	maxJSONNodes   = 500
	maxMapValueLen = 256
	maxImports     = 200
)

var (
	StackNameRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	instanceNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)
	mapKeyRe       = regexp.MustCompile(`^[A-Za-z0-9_.:/@+-]{1,128}$`)
	refRe          = regexp.MustCompile(`^([a-z][a-z0-9_]{0,40})\.([A-Za-z_][A-Za-z0-9_-]{0,63})$`)
	// module.<instance>[.module.<child>[key]]*.<type>.<name>[key]
	importToRe = regexp.MustCompile(`^module\.([a-z][a-z0-9_]{0,40})(\.module\.[A-Za-z_][A-Za-z0-9_-]{0,63}(\[(\d{1,4}|"[A-Za-z0-9_.:/@-]{1,128}")\])?){0,4}\.[a-z][a-z0-9_]{0,63}\.[A-Za-z_][A-Za-z0-9_-]{0,63}(\[(\d{1,4}|"[A-Za-z0-9_.:/@-]{1,128}")\])?$`)
	importIDRe = regexp.MustCompile(`^[\x21-\x7e]+$`)
	// vault://<mount>/<path>#<key>: a KV v2 secret in OpenBao or Vault.
	secretRe = regexp.MustCompile(`^vault://([A-Za-z0-9_.-]{1,64})/([A-Za-z0-9_.-]{1,64}(?:/[A-Za-z0-9_.-]{1,64}){0,7})#([A-Za-z0-9_.-]{1,128})$`)
)

// Stack is what a user submits. It contains no expressions and no HCL.
type Stack struct {
	Modules []ModuleRef `json:"modules"`
	Outputs []Output    `json:"outputs,omitempty"`
	// Imports adopt existing cloud resources into a module's state
	// ("backporting"): instead of creating them, the plan imports them.
	Imports []Import `json:"imports,omitempty"`
}

// Import names an address inside one of the stack's module instances and the
// cloud ID of the existing resource to adopt there.
type Import struct {
	To string `json:"to"`
	ID string `json:"id"`
}

type ModuleRef struct {
	Name    string                     `json:"name"`              // instance name, e.g. "network"
	Kind    string                     `json:"kind,omitempty"`    // e.g. "VPC"; Module is filled in from it
	Module  string                     `json:"module,omitempty"`  // catalog id, e.g. "aws-vpc"
	Version string                     `json:"version,omitempty"` // must be catalog-approved; empty = latest approved
	Inputs  map[string]json.RawMessage `json:"inputs,omitempty"`
}

type Output struct {
	Name      string `json:"name"`
	Module    string `json:"module"` // instance name
	Output    string `json:"output"` // catalog-declared output
	Sensitive bool   `json:"sensitive,omitempty"`
}

// Decode parses a stack spec strictly: unknown fields are an error.
func Decode(b []byte) (*Stack, error) {
	var s Stack
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("invalid stack spec: %w", err)
	}
	if dec.More() {
		return nil, errors.New("invalid stack spec: trailing data")
	}
	return &s, nil
}

// Options carries what validation needs beyond the catalog: the tenant's
// defaults and the environment tier they are picked for.
type Options struct {
	Defaults *catalog.Overlay
	Tier     string
}

// Validate checks a spec against the catalog for the given environment cloud.
// It returns every problem found, not just the first.
func (s *Stack) Validate(cat *catalog.Catalog, cloud string) error {
	return s.ValidateWith(cat, cloud, Options{})
}

// ValidateWith is Validate with the tenant's defaults: required inputs may be
// satisfied by a default, and the default version comes from the tenant.
func (s *Stack) ValidateWith(cat *catalog.Catalog, cloud string, opts Options) error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if len(s.Modules) == 0 {
		add("a stack needs at least one module")
	}
	if len(s.Modules) > maxModules {
		add("a stack may use at most %d modules", maxModules)
	}
	instances := map[string]*catalog.Module{}
	for i := range s.Modules {
		m := &s.Modules[i]
		if !instanceNameRe.MatchString(m.Name) {
			add("module %q: name must match %s", m.Name, instanceNameRe)
			continue
		}
		if instances[m.Name] != nil {
			add("module %q: duplicate name", m.Name)
			continue
		}
		var cm *catalog.Module
		switch {
		case m.Module != "":
			if cm = cat.Module(m.Module); cm == nil {
				add("module %q: %q is not in the approved catalog (only pinned public registry modules can be used)", m.Name, m.Module)
				continue
			}
			if m.Kind != "" && m.Kind != cm.Kind {
				add("module %q: module %s is kind %s, not %s", m.Name, cm.ID, cm.Kind, m.Kind)
				continue
			}
		case m.Kind != "":
			if cm = cat.Kind(m.Kind); cm == nil {
				add("resource %q: %q is not a kind in the approved catalog", m.Name, m.Kind)
				continue
			}
		default:
			add("resource %q: name its kind", m.Name)
			continue
		}
		m.Module, m.Kind = cm.ID, cm.Kind
		if m.Version == "" {
			if d := opts.Defaults.For(cm.Kind); d != nil && d.Version != "" {
				m.Version = d.Version
			} else {
				m.Version = cm.LatestVersion()
			}
		}
		if !cm.HasVersion(m.Version) {
			add("module %q: version %q of %s is not approved (approved: %s)", m.Name, m.Version, cm.ID, strings.Join(cm.Versions, ", "))
		}
		if cm.Cloud != "" && cm.Cloud != cloud {
			add("module %q: %s is a %s module but the environment's cloud is %q", m.Name, cm.ID, cm.Cloud, cloud)
		}
		instances[m.Name] = cm
	}
	for _, m := range s.Modules {
		cm := instances[m.Name]
		if cm == nil {
			continue
		}
		for name, raw := range m.Inputs {
			in := cm.Input(name)
			if in == nil {
				if _, enforced := cm.Enforced[name]; enforced {
					add("module %q: input %q is enforced by the catalog baseline and cannot be changed", m.Name, name)
				} else {
					add("module %q: input %q is not an allowed input of %s", m.Name, name, cm.ID)
				}
				continue
			}
			if err := validateValue(in, raw, m.Name, instances); err != nil {
				add("module %q: input %q: %v", m.Name, name, err)
			}
		}
		vals, _ := effectiveInputs(cm, m, opts)
		for _, in := range cm.Inputs {
			if _, set := vals[in.Name]; in.Required && !set {
				add("module %q: input %q is required (set it in the contract or as a tenant default)", m.Name, in.Name)
			}
			// A map merged from defaults and the contract can outgrow its limits.
			if _, own := m.Inputs[in.Name]; own && strings.HasPrefix(in.Type, "map(") {
				if err := validateValue(in, vals[in.Name], m.Name, instances); err != nil {
					add("module %q: input %q with defaults merged: %v", m.Name, in.Name, err)
				}
			}
		}
	}
	if len(s.Imports) > maxImports {
		add("a stack may import at most %d resources at once", maxImports)
	}
	seenTo := map[string]bool{}
	for _, im := range s.Imports {
		m := importToRe.FindStringSubmatch(im.To)
		switch {
		case m == nil:
			add("import %q: to must be an address inside a module, e.g. module.network.aws_vpc.this[0]", im.To)
		case instances[m[1]] == nil:
			add("import %q: no module named %q in this stack", im.To, m[1])
		case seenTo[im.To]:
			add("import %q: duplicate address", im.To)
		case len(im.ID) > 2048 || !importIDRe.MatchString(im.ID) || hasTemplate(im.ID):
			add("import %q: id must be the resource's literal cloud ID (no spaces or template sequences)", im.To)
		}
		seenTo[im.To] = true
	}
	outNames := map[string]bool{}
	for _, o := range s.Outputs {
		if !instanceNameRe.MatchString(o.Name) || outNames[o.Name] {
			add("output %q: invalid or duplicate name", o.Name)
			continue
		}
		outNames[o.Name] = true
		cm := instances[o.Module]
		if cm == nil {
			add("output %q: unknown module %q", o.Name, o.Module)
		} else if !cm.HasOutput(o.Output) {
			add("output %q: %s has no approved output %q", o.Name, cm.ID, o.Output)
		}
	}
	return errors.Join(errs...)
}

// validateValue checks one input value against its catalog schema.
func validateValue(in *catalog.Input, raw json.RawMessage, self string, instances map[string]*catalog.Module) error {
	v, err := decodeAny(raw)
	if err != nil {
		return err
	}
	if ref, ok, err := asRef(v); ok || err != nil {
		if err != nil {
			return err
		}
		if instances == nil {
			return errors.New("defaults cannot reference other resources")
		}
		return checkRef(ref, self, instances)
	}
	if sec, ok, err := asSecret(v); ok || err != nil {
		if err != nil {
			return err
		}
		if in.Type != "string" {
			return errors.New("a secret reference can only fill a string input")
		}
		return checkSecret(sec)
	}
	if in.Sensitive {
		return errors.New("is sensitive: pass a secretRef (vault://mount/path#key), never the value itself")
	}
	if err := noTemplates(v, 0, new(int)); err != nil {
		return err
	}
	if err := noSecretValues(v); err != nil {
		return err
	}
	switch in.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			return errors.New("must be a string")
		}
		if len(s) > maxStringLen {
			return errors.New("too long")
		}
		if re := in.PatternRe(); re != nil && !re.MatchString(s) {
			return fmt.Errorf("must match %s", in.Pattern)
		}
	case "number":
		n, ok := v.(json.Number)
		if !ok {
			return errors.New("must be a number")
		}
		f, err := n.Float64()
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return errors.New("invalid number")
		}
		if in.Min != nil && f < *in.Min || in.Max != nil && f > *in.Max {
			return errors.New("out of range")
		}
	case "bool":
		if _, ok := v.(bool); !ok {
			return errors.New("must be true or false")
		}
	case "list(string)", "list(number)":
		xs, ok := v.([]any)
		if !ok {
			return errors.New("must be a list")
		}
		limit := maxListItems
		if in.MaxItems > 0 {
			limit = in.MaxItems
		}
		if len(xs) > limit {
			return fmt.Errorf("at most %d items", limit)
		}
		for _, x := range xs {
			if in.Type == "list(number)" {
				if _, ok := x.(json.Number); !ok {
					return errors.New("items must be numbers")
				}
				continue
			}
			s, ok := x.(string)
			if !ok || len(s) > maxStringLen {
				return errors.New("items must be short strings")
			}
			if re := in.ItemPatternRe(); re != nil && !re.MatchString(s) {
				return fmt.Errorf("item %q must match %s", s, in.ItemPattern)
			}
		}
	case "map(string)", "map(bool)":
		m, ok := v.(map[string]any)
		if !ok {
			return errors.New("must be an object")
		}
		if len(m) > maxMapEntries {
			return fmt.Errorf("at most %d entries", maxMapEntries)
		}
		for k, x := range m {
			if !mapKeyRe.MatchString(k) {
				return fmt.Errorf("key %q is not allowed", k)
			}
			if in.Type == "map(bool)" {
				if _, ok := x.(bool); !ok {
					return errors.New("values must be true or false")
				}
			} else if s, ok := x.(string); !ok || len(s) > maxMapValueLen {
				return errors.New("values must be short strings")
			}
		}
	case "json":
		// Structure is checked by the module's own type constraints at plan
		// time; here we only bound size and forbid expressions (noTemplates).
	default:
		return fmt.Errorf("unsupported type %q", in.Type)
	}
	if len(in.Allowed) > 0 && !allowed(in.Allowed, v) {
		return fmt.Errorf("must be one of %v", in.Allowed)
	}
	return nil
}

func decodeAny(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return v, nil
}

// noTemplates rejects any string or key containing an OpenTofu template
// sequence. In JSON configuration every string is parsed as a template, so
// "${file(\"/etc/passwd\")}" or "%{ for ... }" would otherwise be evaluated.
func noTemplates(v any, depth int, nodes *int) error {
	*nodes++
	if *nodes > maxJSONNodes {
		return errors.New("value is too large")
	}
	if depth > maxJSONDepth {
		return errors.New("value is nested too deeply")
	}
	switch t := v.(type) {
	case string:
		if hasTemplate(t) {
			return errors.New("expressions and template sequences (${ } or %{ }) are not allowed")
		}
		if len(t) > maxStringLen {
			return errors.New("string too long")
		}
	case []any:
		for _, x := range t {
			if err := noTemplates(x, depth+1, nodes); err != nil {
				return err
			}
		}
	case map[string]any:
		for k, x := range t {
			if hasTemplate(k) || !mapKeyRe.MatchString(k) {
				return fmt.Errorf("key %q is not allowed", k)
			}
			if k == "$ref" {
				return errors.New("$ref is only allowed as a whole input value")
			}
			if err := noTemplates(x, depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

func hasTemplate(s string) bool { return strings.Contains(s, "${") || strings.Contains(s, "%{") }

// asRef recognises {"$ref": "instance.output"}, the only way to wire modules together.
func asRef(v any) (string, bool, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false, nil
	}
	r, has := m["$ref"]
	if !has {
		return "", false, nil
	}
	s, ok := r.(string)
	if !ok || len(m) != 1 {
		return "", true, errors.New(`a reference must be exactly {"$ref": "module.output"}`)
	}
	return s, true, nil
}

func checkRef(ref, self string, instances map[string]*catalog.Module) error {
	p := refRe.FindStringSubmatch(ref)
	if p == nil {
		return fmt.Errorf("reference %q must look like module_name.output", ref)
	}
	if p[1] == self {
		return errors.New("a module cannot reference itself")
	}
	cm := instances[p[1]]
	if cm == nil {
		return fmt.Errorf("reference %q: no module named %q in this stack", ref, p[1])
	}
	if !cm.HasOutput(p[2]) {
		return fmt.Errorf("reference %q: %s has no approved output %q", ref, cm.ID, p[2])
	}
	return nil
}

func allowed(list []any, v any) bool {
	for _, a := range list {
		if n, ok := a.(json.Number); ok {
			f, _ := n.Float64()
			a = f
		}
		switch av := a.(type) {
		case string:
			if s, ok := v.(string); ok && s == av {
				return true
			}
		case float64:
			if n, ok := v.(json.Number); ok {
				if f, err := n.Float64(); err == nil && f == av {
					return true
				}
			}
		case bool:
			if b, ok := v.(bool); ok && b == av {
				return true
			}
		}
	}
	return false
}

// asSecret recognises {"$secret": "vault://mount/path#key"}: the value lives
// in the tenant's secret store and is read by the run itself.
func asSecret(v any) (string, bool, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false, nil
	}
	r, has := m["$secret"]
	if !has {
		return "", false, nil
	}
	s, ok := r.(string)
	if !ok || len(m) != 1 {
		return "", true, errors.New(`a secret reference must be exactly {"secretRef": "vault://mount/path#key"}`)
	}
	return s, true, nil
}

func checkSecret(ref string) error {
	if !secretRe.MatchString(ref) || strings.Contains(ref, "..") {
		return fmt.Errorf("secret reference %q must look like vault://<mount>/<path>#<key>", ref)
	}
	return nil
}

// noSecretValues refuses literal values that look like credentials: they
// belong in the secret store, referenced with secretRef.
func noSecretValues(v any) error {
	switch t := v.(type) {
	case string:
		if redact.LooksLikeSecret(t) {
			return errors.New("looks like a credential; store it in the secret store and pass a secretRef instead")
		}
	case []any:
		for _, x := range t {
			if err := noSecretValues(x); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, x := range t {
			if err := noSecretValues(x); err != nil {
				return err
			}
		}
	}
	return nil
}

// effectiveInputs layers a resource's inputs: kind defaults, then the
// tenant's defaults, then the tenant's tier defaults, then the resource's own
// values. Maps of strings (tags, labels) merge key by key; everything else is
// replaced by the more specific layer. from lists the default layers used.
func effectiveInputs(cm *catalog.Module, m ModuleRef, opts Options) (map[string]json.RawMessage, []string) {
	vals := map[string]json.RawMessage{}
	var from []string
	layer := func(src map[string]json.RawMessage, label string) {
		used := false
		for k, raw := range src {
			in := cm.Input(k)
			if in == nil {
				continue
			}
			used = true
			if prev, ok := vals[k]; ok && strings.HasPrefix(in.Type, "map(") {
				if merged, ok := mergeMaps(prev, raw); ok {
					vals[k] = merged
					continue
				}
			}
			vals[k] = raw
		}
		if used && label != "" {
			from = append(from, label)
		}
	}
	kind := map[string]json.RawMessage{}
	for _, in := range cm.Inputs {
		if in.Default != nil {
			kind[in.Name], _ = json.Marshal(in.Default)
		}
	}
	layer(kind, "kind")
	if d := opts.Defaults.For(cm.Kind); d != nil {
		layer(d.Spec, "tenant "+opts.Defaults.Tenant)
		if opts.Tier != "" {
			layer(d.Tiers[opts.Tier], "tenant "+opts.Defaults.Tenant+" ("+opts.Tier+")")
		}
	}
	layer(m.Inputs, "")
	return vals, from
}

func mergeMaps(a, b json.RawMessage) (json.RawMessage, bool) {
	var x, y map[string]any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return nil, false
	}
	if _, ref := y["$ref"]; ref {
		return nil, false
	}
	if _, ref := x["$ref"]; ref {
		return nil, false
	}
	for k, v := range y {
		x[k] = v
	}
	out, err := json.Marshal(x)
	return out, err == nil
}

// ValidateOverlay checks a tenant's defaults against the catalog: every value
// must be an allowed input of its kind and pass the same checks as a contract
// value. Defaults may hold secret references but never resource references.
func ValidateOverlay(cat *catalog.Catalog, ov *catalog.Overlay) error {
	var errs []error
	for _, kind := range ov.KindNames() {
		d := ov.Kinds[kind]
		cm := cat.Kind(kind)
		check := func(where string, vals map[string]json.RawMessage) {
			for name, raw := range vals {
				in := cm.Input(name)
				if in == nil {
					if _, enforced := cm.Enforced[name]; enforced {
						errs = append(errs, fmt.Errorf("%s: %s is enforced by the baseline and cannot be defaulted", where, name))
					} else {
						errs = append(errs, fmt.Errorf("%s: %s is not an input of %s", where, name, kind))
					}
					continue
				}
				if err := validateValue(in, raw, "", nil); err != nil {
					errs = append(errs, fmt.Errorf("%s: %s: %v", where, name, err))
				}
			}
		}
		check(d.File, d.Spec)
		for tier, vals := range d.Tiers {
			check(d.File+" (tier "+tier+")", vals)
		}
	}
	return errors.Join(errs...)
}

// Vault is a tenant's secret store (OpenBao or HashiCorp Vault, KV v2). It
// holds no credentials: runs log in with their own short-lived OIDC token
// through the JWT auth method, and the Vault role decides what they may read.
type Vault struct {
	Address   string `json:"address"`              // https://bao.example.internal:8200
	AuthMount string `json:"auth_mount,omitempty"` // JWT auth mount; default "jwt"
	Role      string `json:"role"`                 // JWT role runs log in as
	Namespace string `json:"namespace,omitempty"`  // Vault Enterprise / OpenBao namespace
	Audience  string `json:"audience,omitempty"`   // "aud" of the run's token; default "pravaha-vault"
}

var (
	vaultNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}(/[A-Za-z0-9_.-]{1,64}){0,3}$`)
	audRe       = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)
)

func (v *Vault) mount() string {
	if v.AuthMount == "" {
		return "jwt"
	}
	return v.AuthMount
}

// TokenAudience is the audience runs' Vault tokens are issued for.
func (v *Vault) TokenAudience() string {
	if v.Audience == "" {
		return "pravaha-vault"
	}
	return v.Audience
}

// Validate checks a secret store configuration. Plain http is accepted only
// on loopback, for development.
func (v *Vault) Validate() error {
	var errs []error
	u, err := url.Parse(v.Address)
	switch {
	case err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "":
		errs = append(errs, errors.New("address must be a URL like https://bao.example.internal:8200"))
	case u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")):
		errs = append(errs, errors.New("address must use https (plain http only on loopback, for development)"))
	}
	if !vaultNameRe.MatchString(v.mount()) {
		errs = append(errs, errors.New("auth_mount is invalid"))
	}
	if !vaultNameRe.MatchString(v.Role) {
		errs = append(errs, errors.New("role is required"))
	}
	if v.Namespace != "" && !vaultNameRe.MatchString(v.Namespace) {
		errs = append(errs, errors.New("namespace is invalid"))
	}
	if v.Audience != "" && !audRe.MatchString(v.Audience) {
		errs = append(errs, errors.New("audience is invalid"))
	}
	return errors.Join(errs...)
}
