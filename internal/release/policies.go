package release

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/tester"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/opapolicy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/yamlx"
)

// PoliciesInput is what a policy release is built from. The folder holds:
//
//	global/<set>.rego                          every tenant
//	tenants/<tenant>/<set>.rego                the whole tenant
//	tenants/<tenant>/entities/<entity>/<set>.rego
//	tenants/<tenant>/bus/<bu>/<set>.rego
//
// next to each set, optionally:
//
//	<set>_test.rego   Rego unit tests (test_* rules), run on every build
//	<set>.yaml        apiVersion: pravaha/v1 / kind: PolicySet / level: hard|advisory / description
//
// Only global/ and this tenant's folder go into the tenant's release.
type PoliciesInput struct {
	Files    map[string][]byte
	Path     string
	Tenant   string
	Revision string
	// Reserved names (policy sets managed in the console) a release may not reuse.
	Reserved map[string]bool
}

var (
	setNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	slugRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

type setMeta struct {
	APIVersion  string `json:"apiVersion"`
	Kind        string `json:"kind"`
	Level       string `json:"level,omitempty"`
	Description string `json:"description,omitempty"`
}

// BuildPolicies compiles every policy set, runs its tests and builds a policy release.
func BuildPolicies(ctx context.Context, in PoliciesInput) *Result {
	res := &Result{Manifest: &Manifest{Kind: Policies, Revision: in.Revision, Tenant: in.Tenant, BuiltAt: time.Now().UTC().Truncate(time.Second)}}
	root := strings.Trim(in.Path, "/")
	rel := func(f string) (string, bool) {
		if root == "" {
			return f, true
		}
		return strings.CutPrefix(f, root+"/")
	}
	type found struct {
		file, scope, name string
		module, test      []byte
		meta              *setMeta
	}
	var sets []*found
	var layoutErrs []error
	byName := map[string]string{}
	for _, f := range sortedKeys(in.Files) {
		r, ok := rel(f)
		if !ok || path.Ext(r) != ".rego" || strings.HasSuffix(r, "_test.rego") {
			continue
		}
		parts := strings.Split(r, "/")
		base := strings.TrimSuffix(parts[len(parts)-1], ".rego")
		var scope, name string
		switch {
		case len(parts) == 2 && parts[0] == "global":
			scope, name = "tenant", base
		case len(parts) >= 3 && parts[0] == "tenants" && parts[1] != in.Tenant:
			continue // another tenant's policies never reach this tenant
		case len(parts) == 3 && parts[0] == "tenants":
			scope, name = "tenant", base
		case len(parts) == 5 && parts[0] == "tenants" && parts[2] == "entities" && slugRe.MatchString(parts[3]):
			scope, name = "entity:"+parts[3], parts[3]+"-"+base
		case len(parts) == 5 && parts[0] == "tenants" && parts[2] == "bus" && slugRe.MatchString(parts[3]):
			scope, name = "bu:"+parts[3], parts[3]+"-"+base
		default:
			layoutErrs = append(layoutErrs, fmt.Errorf("%s: policy sets live in global/, tenants/<tenant>/, tenants/<tenant>/entities/<entity>/ or tenants/<tenant>/bus/<bu>/", f))
			continue
		}
		if !setNameRe.MatchString(name) {
			layoutErrs = append(layoutErrs, fmt.Errorf("%s: the set name %q must be lowercase letters, digits and dashes", f, name))
			continue
		}
		if other, dup := byName[name]; dup {
			layoutErrs = append(layoutErrs, fmt.Errorf("%s: set %q is also defined by %s", f, name, other))
			continue
		}
		if in.Reserved[name] {
			layoutErrs = append(layoutErrs, fmt.Errorf("%s: a policy set named %q is managed in the console; rename one of them", f, name))
			continue
		}
		byName[name] = f
		s := &found{file: r, scope: scope, name: name, module: in.Files[f], test: in.Files[strings.TrimSuffix(f, ".rego")+"_test.rego"]}
		if b, ok := in.Files[strings.TrimSuffix(f, ".rego")+".yaml"]; ok {
			var m setMeta
			if err := yamlx.Decode(b, &m); err != nil {
				layoutErrs = append(layoutErrs, fmt.Errorf("%s.yaml: %v", strings.TrimSuffix(f, ".rego"), err))
				continue
			}
			if m.APIVersion != "pravaha/v1" || m.Kind != "PolicySet" || (m.Level != "" && m.Level != "hard" && m.Level != "advisory") {
				layoutErrs = append(layoutErrs, fmt.Errorf("%s.yaml: needs apiVersion pravaha/v1, kind PolicySet and level hard or advisory", strings.TrimSuffix(f, ".rego")))
				continue
			}
			s.meta = &m
		}
		sets = append(sets, s)
	}
	if !res.check("Policy layout", layoutErrs, fmt.Sprintf("%d policy sets for tenant %s", len(sets), in.Tenant)) {
		return res
	}

	var compileErrs, testErrs []error
	tests, untested := 0, 0
	files := map[string][]byte{}
	for _, s := range sets {
		if err := opapolicy.Compile(string(s.module)); err != nil {
			compileErrs = append(compileErrs, fmt.Errorf("%s: %v", s.file, err))
			continue
		}
		ps := PolicySet{Name: s.name, Scope: s.scope, Level: "hard", Module: string(s.module), File: s.file}
		if s.meta != nil {
			ps.Description = s.meta.Description
			if s.meta.Level != "" {
				ps.Level = s.meta.Level
			}
		}
		if s.test == nil {
			untested++
		} else {
			n, err := runTests(ctx, s.file, s.module, s.test)
			if err != nil {
				testErrs = append(testErrs, err)
			}
			ps.Tests, tests = n, tests+n
			files[strings.TrimSuffix(s.file, ".rego")+"_test.rego"] = s.test
		}
		files[s.file] = s.module
		res.Manifest.Policies = append(res.Manifest.Policies, ps)
	}
	sort.Slice(res.Manifest.Policies, func(i, j int) bool { return res.Manifest.Policies[i].Name < res.Manifest.Policies[j].Name })
	res.check("Policy sets compile", compileErrs, "every set declares package "+opapolicy.Package)
	detail := fmt.Sprintf("%d tests passed", tests)
	if untested > 0 {
		detail += fmt.Sprintf("; %d sets have no tests", untested)
	}
	res.check("Policy tests", testErrs, detail)
	if !res.OK() {
		return res
	}
	bundle, sum, err := Pack(res.Manifest, files)
	if res.check("Bundle", errs(err), fmt.Sprintf("%d files", len(files)+1)) {
		res.Bundle, res.SHA256 = bundle, sum
	}
	return res
}

// runTests runs one set's Rego tests against that set alone, exactly as
// sets are evaluated (each on its own).
func runTests(ctx context.Context, file string, module, test []byte) (int, error) {
	opts := ast.ParserOptions{RegoVersion: ast.RegoV1}
	m, err := ast.ParseModuleWithOpts(file, string(module), opts)
	if err != nil {
		return 0, err
	}
	tf := strings.TrimSuffix(file, ".rego") + "_test.rego"
	t, err := ast.ParseModuleWithOpts(tf, string(test), opts)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", tf, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ch, err := tester.NewRunner().SetModules(map[string]*ast.Module{file: m, tf: t}).SetTimeout(5*time.Second).RunTests(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %v", tf, err)
	}
	n := 0
	var fails []string
	for r := range ch {
		if r.Skip {
			continue
		}
		n++
		if r.Error != nil {
			fails = append(fails, fmt.Sprintf("%s: %s errored: %v", tf, r.Name, r.Error))
		} else if r.Fail {
			fails = append(fails, fmt.Sprintf("%s: %s failed", tf, r.Name))
		}
	}
	if n == 0 {
		return 0, fmt.Errorf("%s holds no test_ rules", tf)
	}
	if len(fails) > 0 {
		return n, errors.New(strings.Join(fails, "\n"))
	}
	return n, nil
}
