package release

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestBuildRealModules builds a release from the sibling modules repository
// against the real registry. It needs the network: PRAVAHA_REGISTRY_TESTS=1.
func TestBuildRealModules(t *testing.T) {
	if os.Getenv("PRAVAHA_REGISTRY_TESTS") == "" {
		t.Skip("set PRAVAHA_REGISTRY_TESTS=1 to build against registry.opentofu.org")
	}
	root := "../../../cloud-pravaha-modules"
	files := map[string][]byte{}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			if b, err := os.ReadFile(p); err == nil {
				files[filepath.ToSlash(rel)] = b
			}
		}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res := BuildModules(ctx, ModulesInput{Files: files, Tenant: "acme", Revision: "local", Fetch: &Registry{}})
	for _, c := range res.Checks {
		t.Logf("%v %s: %s", c.OK, c.Name, c.Detail)
		for _, e := range c.Errors {
			t.Logf("    %s", e)
		}
	}
	if !res.OK() {
		t.Fatal("build failed")
	}
	t.Logf("bundle %s (%d bytes)", res.SHA256[:12], len(res.Bundle))
}

// TestVendoredModulesWithTofu unpacks a real release and runs tofu init and
// validate on modules loaded only from vendor/ (PRAVAHA_TOFU_TESTS=1).
func TestVendoredModulesWithTofu(t *testing.T) {
	if os.Getenv("PRAVAHA_TOFU_TESTS") == "" {
		t.Skip("set PRAVAHA_TOFU_TESTS=1 (needs tofu and the network)")
	}
	root := "../../../cloud-pravaha-modules"
	files := map[string][]byte{}
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			if b, err := os.ReadFile(p); err == nil {
				files[filepath.ToSlash(rel)] = b
			}
		}
		return nil
	})
	ctx := context.Background()
	res := BuildModules(ctx, ModulesInput{Files: files, Tenant: "acme", Revision: "local", Fetch: &Registry{}})
	if !res.OK() {
		t.Fatalf("%+v", res.Checks)
	}
	dir := t.TempDir()
	if _, err := Unpack(res.Bundle, res.SHA256, nil, func(name string, b []byte) error {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		return os.WriteFile(p, b, 0o644)
	}); err != nil {
		t.Fatal(err)
	}
	m := res.Manifest.Modules
	main := fmt.Sprintf(`
module "naming" {
  source = "./%s"
  suffix = ["demo"]
}
module "label" {
  source = "./%s"
  name   = "demo"
}
module "eks" {
  source          = "./%s"
  name            = "demo"
  kubernetes_version = "1.33"
}
`, m["Azure/naming/azurerm@0.4.4"], m["cloudposse/label/null@0.25.0"], firstMatch(m, "terraform-aws-modules/eks/aws@"))
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(main), 0o644)
	for _, args := range [][]string{{"init", "-backend=false", "-input=false", "-no-color"}, {"validate", "-no-color"}} {
		cmd := exec.CommandContext(ctx, "tofu", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		t.Logf("tofu %s:\n%s", args[0], out)
		if err != nil {
			t.Fatalf("tofu %s failed: %v", args[0], err)
		}
		if args[0] == "init" && strings.Contains(string(out), "Downloading") {
			t.Fatal("tofu downloaded a module; everything must come from vendor/")
		}
	}
}

func firstMatch(m map[string]string, prefix string) string {
	for k, v := range m {
		if strings.HasPrefix(k, prefix) {
			return v
		}
	}
	return ""
}
