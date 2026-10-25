package contracts

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/yamlx"
)

// A contract file describes one resource, Kubernetes style, and holds only
// what differs from the defaults of its kind:
//
//	apiVersion: pravaha/v1
//	kind: S3Bucket
//	metadata:
//	  name: orders              # defaults to the file name
//	  version: 5.17.0           # optional pin; otherwise the tenant's default
//	spec:
//	  bucket: acme-orders-dev
//	  kms_key_arn:
//	    ref: orders-key.key_arn # another resource of the same stack
//	  master_password:
//	    secretRef: vault://kv/orders/db#password
//	imports:                    # optional: adopt existing resources
//	  - to: aws_s3_bucket.this[0]
//	    id: acme-orders-dev
//	outputs:
//	  - name: orders_bucket_arn
//	    value: s3_bucket_arn
//
// The folder holding the files is the stack. With the nested layout the
// folders name the entity, environment and BU; with the flat layout the
// files name them in metadata (and must agree).

// APIVersion is the only contract version.
const APIVersion = "pravaha/v1"

// Contract is one stack assembled from the resource files in its folder.
type Contract struct {
	File        string          `json:"file"`  // the stack folder
	Files       []string        `json:"files"` // its resource files
	Name        string          `json:"name"`
	Environment string          `json:"environment"`
	Spec        json.RawMessage `json:"spec"` // a stack spec (internal/spec)
	BU          string          `json:"bu,omitempty"`
	Entity      string          `json:"-"` // nested layout: the entity (product) folder
}

type resource struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string `json:"name,omitempty"`
		Version     string `json:"version,omitempty"`
		Environment string `json:"environment,omitempty"`
		BU          string `json:"bu,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"metadata"`
	Spec    map[string]json.RawMessage `json:"spec,omitempty"`
	Imports []struct {
		To string `json:"to"`
		ID string `json:"id"`
	} `json:"imports,omitempty"`
	Outputs []struct {
		Name      string `json:"name"`
		Value     string `json:"value"`
		Sensitive bool   `json:"sensitive,omitempty"`
	} `json:"outputs,omitempty"`
}

var (
	// Resource names: lowercase, digits, - and _. Hyphens become underscores
	// in the generated module name (orders-db -> module.orders_db).
	resourceNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,40}$`)
	refValueRe     = regexp.MustCompile(`^([a-z][a-z0-9_-]{0,40})\.([A-Za-z_][A-Za-z0-9_-]{0,63})$`)
)

// ModuleName is the module instance name generated for a resource name.
func ModuleName(resource string) string { return strings.ReplaceAll(resource, "-", "_") }

func isYAML(f string) bool { return path.Ext(f) == ".yaml" || path.Ext(f) == ".yml" }

// Parse reads contracts with the flat layout.
func Parse(files map[string][]byte, dir string) ([]Contract, map[string]string) {
	return ParseLayout(files, dir, "flat")
}

// ParseLayout groups the YAML files under dir into stacks by folder and turns
// each stack into a spec. Problems are returned per file (or per stack
// folder); a stack with any problem is left out entirely, so a half-read
// stack is never applied.
func ParseLayout(files map[string][]byte, dir, layout string) ([]Contract, map[string]string) {
	dir = strings.Trim(dir, "/")
	depth := 2 // <stack>/<resource>.yaml
	if layout == "nested" {
		depth = 5 // <entity>/<environment>/<bu>/<stack>/<resource>.yaml
	}
	problems := map[string]string{}
	stacks := map[string][]string{}
	for f := range files {
		if !isYAML(f) {
			continue
		}
		rel, inside := f, true
		if dir != "" {
			rel, inside = strings.CutPrefix(f, dir+"/")
		}
		if !inside {
			continue
		}
		if parts := strings.Split(rel, "/"); len(parts) != depth {
			want := "<stack>/<resource>.yaml"
			if layout == "nested" {
				want = "<entity>/<environment>/<bu>/<stack>/<resource>.yaml"
			}
			problems[f] = "contracts live at " + path.Join(dir, want) + " (one resource per file; the folder is the stack)"
			continue
		}
		stacks[path.Dir(f)] = append(stacks[path.Dir(f)], f)
	}
	folders := make([]string, 0, len(stacks))
	for d := range stacks {
		folders = append(folders, d)
	}
	sort.Strings(folders)
	var out []Contract
	for _, folder := range folders {
		fs := stacks[folder]
		sort.Strings(fs)
		c, probs := parseStack(folder, fs, files, dir, layout)
		if len(probs) > 0 {
			for f, p := range probs {
				problems[f] = p
			}
			continue
		}
		out = append(out, c)
	}
	return out, problems
}

func parseStack(folder string, fs []string, files map[string][]byte, dir, layout string) (Contract, map[string]string) {
	probs := map[string]string{}
	c := Contract{File: folder, Files: fs, Name: path.Base(folder)}
	if layout == "nested" {
		rel := strings.TrimPrefix(folder, dir+"/")
		if dir == "" {
			rel = folder
		}
		parts := strings.Split(rel, "/")
		c.Entity, c.Environment, c.BU = parts[0], parts[1], parts[2]
	}
	type entry struct {
		file string
		r    resource
	}
	var res []entry
	for _, f := range fs {
		docs, err := yamlx.Documents(files[f])
		if err != nil {
			probs[f] = err.Error()
			continue
		}
		if len(docs) == 0 {
			probs[f] = "the file is empty"
			continue
		}
		for i, d := range docs {
			var r resource
			if err := yamlx.DecodeJSON(d, &r); err != nil {
				probs[f] = "invalid contract: " + err.Error()
				break
			}
			if r.Metadata.Name == "" {
				if len(docs) > 1 {
					probs[f] = fmt.Sprintf("document %d: metadata.name is required when a file holds several resources", i+1)
					break
				}
				r.Metadata.Name = strings.TrimSuffix(path.Base(f), path.Ext(f))
			}
			res = append(res, entry{f, r})
		}
	}
	if len(probs) > 0 {
		return c, probs
	}

	// Stack placement: folders (nested) or metadata (flat), never in conflict.
	for _, e := range res {
		m := e.r.Metadata
		for _, kv := range []struct {
			field, got string
			want       *string
		}{{"environment", m.Environment, &c.Environment}, {"business unit", m.BU, &c.BU}} {
			switch {
			case kv.got == "":
			case *kv.want == "":
				*kv.want = kv.got
			case *kv.want != kv.got:
				where := "another file of this stack"
				if layout == "nested" {
					where = "its folder"
				}
				probs[e.file] = fmt.Sprintf("metadata names %s %q but %s says %q", kv.field, kv.got, where, *kv.want)
			}
		}
	}
	if c.Environment == "" {
		probs[folder] = "no file of this stack names its environment (metadata.environment)"
	}
	if c.BU == "" {
		probs[folder] = "no file of this stack names its business unit (metadata.bu)"
	}

	type module struct {
		Name    string                     `json:"name"`
		Kind    string                     `json:"kind"`
		Version string                     `json:"version,omitempty"`
		Inputs  map[string]json.RawMessage `json:"inputs,omitempty"`
	}
	type imp struct {
		To string `json:"to"`
		ID string `json:"id"`
	}
	type output struct {
		Name      string `json:"name"`
		Module    string `json:"module"`
		Output    string `json:"output"`
		Sensitive bool   `json:"sensitive,omitempty"`
	}
	var spec struct {
		Modules []module `json:"modules"`
		Outputs []output `json:"outputs,omitempty"`
		Imports []imp    `json:"imports,omitempty"`
	}
	seen := map[string]string{} // module name -> file
	for _, e := range res {
		r, f := e.r, e.file
		switch {
		case r.APIVersion != APIVersion:
			probs[f] = "apiVersion must be " + APIVersion
			continue
		case r.Kind == "":
			probs[f] = "kind is required (a kind from the catalog, e.g. S3Bucket)"
			continue
		case !resourceNameRe.MatchString(r.Metadata.Name):
			probs[f] = fmt.Sprintf("resource name %q must be lowercase letters, digits, - or _ (at most 41)", r.Metadata.Name)
			continue
		}
		name := ModuleName(r.Metadata.Name)
		if other, dup := seen[name]; dup {
			probs[f] = fmt.Sprintf("resource %q is also defined in %s", r.Metadata.Name, other)
			continue
		}
		seen[name] = f
		inputs := map[string]json.RawMessage{}
		for k, v := range r.Spec {
			conv, err := convertValue(v)
			if err != nil {
				probs[f] = fmt.Sprintf("spec.%s: %v", k, err)
				break
			}
			inputs[k] = conv
		}
		spec.Modules = append(spec.Modules, module{Name: name, Kind: r.Kind, Version: r.Metadata.Version, Inputs: inputs})
		for _, im := range r.Imports {
			// Addresses are relative to the resource's module.
			to := "module." + name + "." + strings.TrimPrefix(im.To, "module."+name+".")
			spec.Imports = append(spec.Imports, imp{To: to, ID: im.ID})
		}
		for _, o := range r.Outputs {
			spec.Outputs = append(spec.Outputs, output{Name: ModuleName(o.Name), Module: name, Output: o.Value, Sensitive: o.Sensitive})
		}
	}
	if len(probs) > 0 {
		return c, probs
	}
	c.Spec, _ = json.Marshal(spec)
	return c, nil
}

// convertValue turns the YAML reference forms into the spec's:
// {ref: res.output} -> {"$ref": "res_module.output"} and
// {secretRef: vault://...} -> {"$secret": "vault://..."}. Only a whole input
// value can be a reference; nested ones are refused by spec validation.
func convertValue(v json.RawMessage) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(v, &m) != nil || len(m) != 1 {
		return v, nil
	}
	if r, ok := m["ref"]; ok {
		var s string
		if json.Unmarshal(r, &s) != nil {
			return nil, fmt.Errorf("ref must be a string like orders-key.key_arn")
		}
		p := refValueRe.FindStringSubmatch(s)
		if p == nil {
			return nil, fmt.Errorf("ref %q must look like <resource>.<output>", s)
		}
		return json.Marshal(map[string]string{"$ref": ModuleName(p[1]) + "." + p[2]})
	}
	if r, ok := m["secretRef"]; ok {
		var s string
		if json.Unmarshal(r, &s) != nil {
			return nil, fmt.Errorf("secretRef must be a string like vault://kv/app/db#password")
		}
		return json.Marshal(map[string]string{"$secret": s})
	}
	return v, nil
}

// Render writes a stack spec as contract files, one per resource, for a stack
// folder. With the flat layout each file names the environment and BU.
func Render(specJSON []byte, environment, bu string, flat bool) (map[string][]byte, error) {
	var spec struct {
		Modules []struct {
			Name    string                     `json:"name"`
			Kind    string                     `json:"kind"`
			Version string                     `json:"version"`
			Inputs  map[string]json.RawMessage `json:"inputs"`
		} `json:"modules"`
		Outputs []struct {
			Name, Module, Output string
			Sensitive            bool
		} `json:"outputs"`
		Imports []struct{ To, ID string } `json:"imports"`
	}
	if err := json.Unmarshal(specJSON, &spec); err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, m := range spec.Modules {
		if m.Kind == "" {
			return nil, fmt.Errorf("resource %s has no kind", m.Name)
		}
		meta := yamlx.Map{{Key: "name", Value: m.Name}}
		if m.Version != "" {
			meta = append(meta, yamlx.KV{Key: "version", Value: m.Version})
		}
		if flat {
			meta = append(meta, yamlx.KV{Key: "environment", Value: environment}, yamlx.KV{Key: "bu", Value: bu})
		}
		doc := yamlx.Map{{Key: "apiVersion", Value: APIVersion}, {Key: "kind", Value: m.Kind}, {Key: "metadata", Value: meta}}
		if len(m.Inputs) > 0 {
			keys := make([]string, 0, len(m.Inputs))
			for k := range m.Inputs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			sp := yamlx.Map{}
			for _, k := range keys {
				sp = append(sp, yamlx.KV{Key: k, Value: yamlValue(m.Inputs[k])})
			}
			doc = append(doc, yamlx.KV{Key: "spec", Value: sp})
		}
		var imps []any
		for _, im := range spec.Imports {
			if rest, ok := strings.CutPrefix(im.To, "module."+m.Name+"."); ok {
				imps = append(imps, yamlx.Map{{Key: "to", Value: rest}, {Key: "id", Value: im.ID}})
			}
		}
		if len(imps) > 0 {
			doc = append(doc, yamlx.KV{Key: "imports", Value: imps})
		}
		var outs []any
		for _, o := range spec.Outputs {
			if o.Module == m.Name {
				om := yamlx.Map{{Key: "name", Value: o.Name}, {Key: "value", Value: o.Output}}
				if o.Sensitive {
					om = append(om, yamlx.KV{Key: "sensitive", Value: true})
				}
				outs = append(outs, om)
			}
		}
		if len(outs) > 0 {
			doc = append(doc, yamlx.KV{Key: "outputs", Value: outs})
		}
		b, err := yamlx.Marshal(doc)
		if err != nil {
			return nil, err
		}
		out[m.Name+".yaml"] = b
	}
	return out, nil
}

// yamlValue writes a spec value back in contract form ($ref -> ref, $secret -> secretRef).
func yamlValue(v json.RawMessage) any {
	var m map[string]string
	if json.Unmarshal(v, &m) == nil && len(m) == 1 {
		if r, ok := m["$ref"]; ok {
			return yamlx.Map{{Key: "ref", Value: r}}
		}
		if s, ok := m["$secret"]; ok {
			return yamlx.Map{{Key: "secretRef", Value: s}}
		}
	}
	return v
}
