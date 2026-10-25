package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing/fstest"
	"time"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/depcheck"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
)

// ModulesInput is what a module release is built from.
type ModulesInput struct {
	Files    map[string][]byte // snapshot of the modules repository at Revision
	Path     string            // folder holding catalog/ and tenants/ ("" = repository root)
	Tenant   string            // only this tenant's defaults go into the release
	Revision string
	Fetch    Fetcher
	// VerifyProviders checks provider versions against the registry (network).
	VerifyProviders func(ctx context.Context, c *catalog.Catalog) error
}

var registryAddrRe = regexp.MustCompile(`^(?:(?:registry\.opentofu\.org|registry\.terraform\.io)/)?([A-Za-z0-9][A-Za-z0-9_-]{0,63}/[A-Za-z0-9][A-Za-z0-9_-]{0,63}/[a-z0-9]{1,32})(//[A-Za-z0-9_./-]+)?$`)

// BuildModules validates the modules repository and builds a module release:
//
//  1. the catalog of kinds loads and passes its rules;
//  2. the tenant's defaults target real kinds and pass input validation;
//  3. every approved module version and declared dependency is downloaded
//     from the registry, pinned to the commit the registry points at;
//  4. nested registry modules are rewritten to vendored, approved versions,
//     and any other source (git, http, s3, ...) fails the build;
//  5. no vendored file runs commands (provisioners, the external data source);
//  6. every kind's inputs, baseline keys and outputs exist in its module.
func BuildModules(ctx context.Context, in ModulesInput) *Result {
	res := &Result{Manifest: &Manifest{Kind: Modules, Revision: in.Revision, Tenant: in.Tenant, BuiltAt: time.Now().UTC().Truncate(time.Second)}}
	root := strings.Trim(in.Path, "/")
	sub := func(dir string) fs.FS {
		m := fstest.MapFS{}
		prefix := path.Join(root, dir) + "/"
		if root == "" && dir == "" {
			prefix = ""
		}
		for name, b := range in.Files {
			if rel, ok := strings.CutPrefix(name, prefix); ok {
				m[rel] = &fstest.MapFile{Data: b, Mode: 0o644}
			}
		}
		return m
	}

	cat, err := catalog.LoadFS(sub("catalog"))
	if !res.check("Catalog of kinds", errs(err), countKinds(cat)) {
		return res
	}
	ov, err := catalog.LoadOverlay(sub(""), "tenants/"+in.Tenant, in.Tenant, cat)
	if err == nil {
		err = spec.ValidateOverlay(cat, ov)
	}
	if !res.check("Defaults for tenant "+in.Tenant, errs(err), fmt.Sprintf("%d kinds with tenant defaults", len(ov.KindNames()))) {
		return res
	}
	res.Manifest.Catalog = &CatalogData{Modules: cat.Modules, Providers: cat.Providers}
	res.Manifest.Defaults = ov

	if in.VerifyProviders != nil {
		res.check("Providers on the registry", errs(in.VerifyProviders(ctx, cat)), fmt.Sprintf("%d providers pinned", len(cat.Providers)))
	}

	// Every package version to vendor: catalog modules and declared dependencies.
	approved := map[string][]string{} // registry package -> approved versions
	for _, m := range cat.Modules {
		approved[catalog.BaseSource(m.Source)] = appendUnique(approved[catalog.BaseSource(m.Source)], m.Versions...)
		for _, d := range m.Dependencies {
			approved[d.Source] = appendUnique(approved[d.Source], d.Versions...)
		}
	}
	type job struct{ src, ver string }
	var jobs []job
	for src, vers := range approved {
		for _, v := range vers {
			jobs = append(jobs, job{src, v})
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].src+jobs[i].ver < jobs[j].src+jobs[j].ver })

	files := map[string][]byte{}
	res.Manifest.Packages = map[string]Package{}
	var mu sync.Mutex
	var fetchErrs []error
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			got, origin, err := in.Fetch.Fetch(ctx, j.src, j.ver)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fetchErrs = append(fetchErrs, err)
				return
			}
			dir := PackageDir(j.src, j.ver)
			for n, b := range got {
				files[dir+"/"+n] = b
			}
			res.Manifest.Packages[j.src+"@"+j.ver] = Package{Dir: dir, Origin: origin}
		}(j)
	}
	wg.Wait()
	if !res.check("Module packages from the registry", fetchErrs, fmt.Sprintf("%d packages vendored", len(res.Manifest.Packages))) {
		return res
	}

	// Map every catalog module source (submodules included) to its directory.
	res.Manifest.Modules = map[string]string{}
	var entries []string
	for _, m := range cat.Modules {
		for _, v := range m.Versions {
			dir := PackageDir(catalog.BaseSource(m.Source), v)
			if i := strings.Index(m.Source, "//"); i >= 0 {
				dir += "/" + strings.Trim(m.Source[i+2:], "/")
			}
			res.Manifest.Modules[m.Source+"@"+v] = dir
			entries = append(entries, dir)
		}
	}

	// Walk the module tree from what kinds load: rewrite nested registry
	// modules to vendored, approved versions and refuse other sources. Module
	// directories nothing loads keep no configuration in the bundle, so they
	// can never run.
	var rewriteErrs, execErrs []error
	rewritten, pruned := 0, 0
	visited := map[string]bool{}
	deps := map[string][]string{} // package dir -> package dirs it loads
	sort.Strings(entries)
	for queue := entries; len(queue) > 0; {
		dir := queue[0]
		queue = queue[1:]
		if visited[dir] {
			continue
		}
		visited[dir] = true
		for _, name := range sortedKeys(files) {
			if path.Dir(name) != dir || !isConfig(name) {
				continue
			}
			if err := depcheck.ExecIn(name, files[name]); err != nil {
				execErrs = append(execErrs, err)
			}
			if strings.HasSuffix(name, ".json") {
				if strings.Contains(string(files[name]), `"module"`) {
					rewriteErrs = append(rewriteErrs, fmt.Errorf("%s: module calls in JSON configuration cannot be vendored", name))
				}
				continue
			}
			out, targets, n, err := rewriteSources(name, files[name], approved, res.Manifest.Packages)
			if err != nil {
				rewriteErrs = append(rewriteErrs, err)
				continue
			}
			files[name] = out
			rewritten += n
			queue = append(queue, targets...)
			from := PackageRootOf(dir)
			for _, t := range targets {
				if to := PackageRootOf(t); to != from {
					deps[from] = appendUnique(deps[from], to)
				}
			}
		}
	}
	for name := range files {
		if isConfig(name) && !visited[path.Dir(name)] {
			delete(files, name)
			pruned++
		}
	}
	byDir := map[string]string{}
	for k, p := range res.Manifest.Packages {
		byDir[p.Dir] = k
	}
	for k, p := range res.Manifest.Packages {
		for _, d := range deps[p.Dir] {
			p.Deps = append(p.Deps, byDir[d])
		}
		sort.Strings(p.Deps)
		// Checksums cover the files as shipped (rewritten and pruned): runs verify exactly these.
		own := map[string][]byte{}
		for name, b := range files {
			if rel, ok := strings.CutPrefix(name, p.Dir+"/"); ok {
				own[rel] = b
				p.Bytes += int64(len(b))
			}
		}
		p.Files, p.SHA256 = len(own), PackageSum(own)
		res.Manifest.Packages[k] = p
	}
	res.check("Nested modules pinned to vendored, approved versions", rewriteErrs, fmt.Sprintf("%d module directories loaded, %d nested calls rewritten, %d unused configuration files left out", len(visited), rewritten, pruned))
	res.check("No command execution in modules", execErrs, "no provisioners or external data sources in any loaded module")

	res.check("Kinds match their modules", checkKinds(cat, res.Manifest.Modules, files), "inputs, baseline keys and outputs exist in every version")

	if !res.OK() {
		return res
	}
	bundle, sum, err := Pack(res.Manifest, files)
	if !res.check("Bundle", errs(err), "") {
		return res
	}
	res.Checks[len(res.Checks)-1].Detail = fmt.Sprintf("%d files, %.1f MiB", len(files)+1, float64(len(bundle))/(1<<20))
	res.Bundle, res.SHA256 = bundle, sum
	return res
}

// PackageSum is the checksum of a package's files (paths relative to the
// package directory). Builds record it; runners recompute it after extracting.
func PackageSum(files map[string][]byte) string {
	h := sha256.New()
	for _, n := range sortedKeys(files) {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// PackageDir is where a registry package version lives in a bundle and in a
// run's working directory.
func PackageDir(source, ver string) string {
	return spec.VendorDir + "/" + catalog.BaseSource(source) + "/" + ver
}

// rewriteSources points nested registry module calls at vendored packages
// and returns the directories the file's module calls load.
func rewriteSources(name string, src []byte, approved map[string][]string, pkgs map[string]Package) ([]byte, []string, int, error) {
	f, diags := hclwrite.ParseConfig(src, name, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, nil, 0, fmt.Errorf("%s: %s", name, diags.Error())
	}
	var targets []string
	dir := path.Dir(name)
	pkgRoot := packageRoot(name)
	n := 0
	for _, b := range f.Body().Blocks() {
		if b.Type() != "module" {
			continue
		}
		label := strings.Join(b.Labels(), ".")
		source, ok := literalString(b.Body().GetAttribute("source"))
		if !ok {
			return nil, nil, 0, fmt.Errorf("%s: module %q has no literal source", name, label)
		}
		if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
			target := path.Join(dir, source)
			if target != pkgRoot && !strings.HasPrefix(target, pkgRoot+"/") {
				return nil, nil, 0, fmt.Errorf("%s: module %q points outside its package (%s)", name, label, source)
			}
			targets = append(targets, target)
			continue
		}
		m := registryAddrRe.FindStringSubmatch(source)
		if m == nil {
			return nil, nil, 0, fmt.Errorf("%s: module %q uses source %q; only registry modules and local paths are allowed", name, label, source)
		}
		constraint, _ := literalString(b.Body().GetAttribute("version"))
		ver, err := pick(approved[m[1]], constraint)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("%s: module %q needs %s %s: %v (declare it under dependencies in the catalog)", name, label, m[1], constraint, err)
		}
		if _, ok := pkgs[m[1]+"@"+ver]; !ok {
			return nil, nil, 0, fmt.Errorf("%s: module %q needs %s %s, which was not vendored", name, label, m[1], ver)
		}
		target := PackageDir(m[1], ver)
		if m[2] != "" {
			target += "/" + strings.Trim(m[2], "/")
		}
		b.Body().SetAttributeValue("source", cty.StringVal(relPath(dir, target)))
		b.Body().RemoveAttribute("version")
		targets = append(targets, target)
		n++
	}
	if n == 0 {
		return src, targets, 0, nil
	}
	return f.Bytes(), targets, n, nil
}

// pick returns the highest approved version satisfying a constraint.
func pick(approved []string, constraint string) (string, error) {
	if len(approved) == 0 {
		return "", errors.New("it is not approved")
	}
	var cs version.Constraints
	if strings.TrimSpace(constraint) != "" {
		var err error
		if cs, err = version.NewConstraint(constraint); err != nil {
			return "", fmt.Errorf("invalid version constraint")
		}
	}
	var best *version.Version
	for _, a := range approved {
		v, err := version.NewVersion(a)
		if err != nil || (cs != nil && !cs.Check(v)) {
			continue
		}
		if best == nil || v.GreaterThan(best) {
			best = v
		}
	}
	if best == nil {
		return "", fmt.Errorf("no approved version (%s) satisfies it", strings.Join(approved, ", "))
	}
	return best.Original(), nil
}

// checkKinds proves each kind matches its module: inputs (or their into
// objects), enforced keys and outputs are declared by every version.
func checkKinds(cat *catalog.Catalog, modules map[string]string, files map[string][]byte) []error {
	var out []error
	for _, m := range cat.Modules {
		for _, v := range m.Versions {
			dir := modules[m.Source+"@"+v]
			vars, outs, err := declarations(dir, files)
			if err != nil {
				out = append(out, fmt.Errorf("%s %s: %v", m.Kind, v, err))
				continue
			}
			for _, in := range m.Inputs {
				name := in.Name
				if in.Into != "" {
					name = in.Into
				}
				if !vars[name] {
					out = append(out, fmt.Errorf("%s %s: input %q is not a variable of %s", m.Kind, v, name, m.Source))
				}
			}
			for k := range m.Enforced {
				if !vars[k] {
					out = append(out, fmt.Errorf("%s %s: baseline key %q is not a variable of %s", m.Kind, v, k, m.Source))
				}
			}
			for _, o := range m.Outputs {
				if !outs[o] {
					out = append(out, fmt.Errorf("%s %s: output %q is not declared by %s", m.Kind, v, o, m.Source))
				}
			}
		}
	}
	return out
}

var declSchema = &hcl.BodySchema{Blocks: []hcl.BlockHeaderSchema{{Type: "variable", LabelNames: []string{"name"}}, {Type: "output", LabelNames: []string{"name"}}}}

func declarations(dir string, files map[string][]byte) (vars, outs map[string]bool, err error) {
	vars, outs = map[string]bool{}, map[string]bool{}
	p := hclparse.NewParser()
	found := false
	for name, b := range files {
		if path.Dir(name) != dir || !isConfig(name) {
			continue
		}
		found = true
		var file *hcl.File
		var diags hcl.Diagnostics
		if strings.HasSuffix(name, ".json") {
			file, diags = p.ParseJSON(b, name)
		} else {
			file, diags = p.ParseHCL(b, name)
		}
		if diags.HasErrors() {
			return nil, nil, fmt.Errorf("%s: %s", name, diags.Error())
		}
		content, _, _ := file.Body.PartialContent(declSchema)
		for _, blk := range content.Blocks {
			if blk.Type == "variable" {
				vars[blk.Labels[0]] = true
			} else {
				outs[blk.Labels[0]] = true
			}
		}
	}
	if !found {
		return nil, nil, fmt.Errorf("no configuration files in %s", dir)
	}
	return vars, outs, nil
}

func literalString(a *hclwrite.Attribute) (string, bool) {
	if a == nil {
		return "", false
	}
	e, diags := hclsyntax.ParseExpression(a.Expr().BuildTokens(nil).Bytes(), "x", hcl.InitialPos)
	if diags.HasErrors() {
		return "", false
	}
	v, diags := e.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.Type().Equals(cty.String) {
		return "", false
	}
	return v.AsString(), true
}

// packageRoot is vendor/<ns>/<name>/<provider>/<version> for a file inside it.
func packageRoot(name string) string { return PackageRootOf(path.Dir(name)) }

// relPath is the relative path from directory from to target, both slash paths.
func relPath(from, target string) string {
	a, b := strings.Split(from, "/"), strings.Split(target, "/")
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	var parts []string
	for range a[i:] {
		parts = append(parts, "..")
	}
	parts = append(parts, b[i:]...)
	rel := strings.Join(parts, "/")
	if !strings.HasPrefix(rel, "../") {
		rel = "./" + rel
	}
	return rel
}

func isConfig(name string) bool {
	for _, ext := range []string{".tf", ".tf.json", ".tofu", ".tofu.json"} {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func errs(err error) []error {
	if err == nil {
		return nil
	}
	return []error{err}
}

func countKinds(c *catalog.Catalog) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%d kinds, %d providers", len(c.Modules), len(c.Providers))
}

func appendUnique(xs []string, more ...string) []string {
	for _, m := range more {
		dup := false
		for _, x := range xs {
			dup = dup || x == m
		}
		if !dup {
			xs = append(xs, m)
		}
	}
	return xs
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
