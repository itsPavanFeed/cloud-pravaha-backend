package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealCatalogIsSegregatedByCloud(t *testing.T) {
	c, err := Load("../../../cloud-pravaha-modules/catalog")
	if err != nil {
		t.Skipf("sibling cloud-pravaha-modules repo not available: %v", err)
	}
	want := map[string]string{"aws-vpc": "aws", "gcp-network": "gcp", "azure-storage-account": "azure", "azure-naming": "", "cloudposse-label": ""}
	for id, cloud := range want {
		if m := c.Module(id); m == nil || m.Cloud != cloud {
			t.Errorf("module %s: want cloud %q, got %+v", id, cloud, m)
		}
	}
	if p, _ := c.Provider("hashicorp/google"); p.Cloud != "gcp" {
		t.Errorf("hashicorp/google should come from providers/gcp.json, got %q", p.Cloud)
	}
}

// layout writes a minimal valid catalog and lets each case break one rule.
func layout(t *testing.T, mutate func(dir string)) error {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	write("providers/aws.json", `{"registry":"registry.opentofu.org","providers":[{"source":"hashicorp/aws","version":"6.70.0"}]}`)
	write("providers/gcp.json", `{"registry":"registry.opentofu.org","providers":[{"source":"hashicorp/google","version":"8.8.0"}]}`)
	write("providers/common.json", `{"registry":"registry.opentofu.org","providers":[{"source":"hashicorp/random","version":"3.9.1"}]}`)
	write("modules/aws/vpc.json", `{"id":"aws-vpc","kind":"VPC","title":"t","description":"d","source":"terraform-aws-modules/vpc/aws","versions":["6.7.3"],"providers":["hashicorp/aws","hashicorp/random"],"inputs":[],"outputs":["vpc_id"]}`)
	if mutate != nil {
		mutate(dir)
	}
	_, err := Load(dir)
	return err
}

func TestLayoutRules(t *testing.T) {
	if err := layout(t, nil); err != nil {
		t.Fatalf("valid layout rejected: %v", err)
	}
	put := func(rel, body string) func(string) {
		return func(dir string) {
			os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
			os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644)
		}
	}
	gcpModuleWithAWSProvider := `{"id":"gcp-x","kind":"GCPX","title":"t","description":"d","source":"terraform-google-modules/network/google","versions":["18.3.1"],"providers":["hashicorp/aws"],"inputs":[],"outputs":[]}`
	cases := map[string]struct {
		mutate func(string)
		want   string
	}{
		"module uses another cloud's provider": {put("modules/gcp/x.json", gcpModuleWithAWSProvider), "cannot use the aws provider"},
		"common module uses a cloud provider":  {put("modules/common/x.json", strings.Replace(gcpModuleWithAWSProvider, "gcp-x", "common-x", 1)), "cannot use the aws provider"},
		"module sets its own cloud":            {put("modules/aws/y.json", `{"id":"aws-y","title":"t","description":"d","cloud":"gcp","source":"a/b/aws","versions":["1.0.0"],"providers":[],"inputs":[],"outputs":[]}`), "folder decides"},
		"unknown cloud folder":                 {put("modules/oci/z.json", `{}`), "unknown cloud folder"},
		"unknown provider file":                {put("providers/oci.json", `{"registry":"registry.opentofu.org","providers":[]}`), "unknown cloud"},
		"provider sets its own cloud":          {put("providers/azure.json", `{"registry":"registry.opentofu.org","providers":[{"source":"Azure/azapi","version":"2.13.0","cloud":"aws"}]}`), "file name decides"},
		"provider listed twice":                {put("providers/azure.json", `{"registry":"registry.opentofu.org","providers":[{"source":"hashicorp/aws","version":"6.70.0"}]}`), "more than once"},
		"old flat module file":                 {put("modules/legacy.json", `{}`), "modules/<cloud>/"},
		"old flat providers.json":              {put("providers.json", `{}`), "old flat layout"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := layout(t, tc.mutate)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestRealCatalogKinds(t *testing.T) {
	c, err := Load("../../../cloud-pravaha-modules/catalog")
	if err != nil {
		t.Skipf("sibling cloud-pravaha-modules repo not available: %v", err)
	}
	if m := c.Kind("S3Bucket"); m == nil || m.ID != "aws-s3-bucket" {
		t.Fatalf("kind S3Bucket: %+v", m)
	}
	for _, m := range c.Modules {
		if c.Kind(m.Kind) != m {
			t.Errorf("module %s: kind %q does not resolve back", m.ID, m.Kind)
		}
	}
	if _, ok := c.Provider("hashicorp/vault"); !ok {
		t.Fatal("the vault provider must be allowlisted for secret references")
	}
}

func TestKindRules(t *testing.T) {
	put := func(rel, body string) func(string) {
		return func(dir string) { os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644) }
	}
	for name, c := range map[string]struct {
		mutate func(string)
		want   string
	}{
		"missing":           {put("modules/aws/vpc.json", `{"id":"aws-vpc","title":"t","description":"d","source":"terraform-aws-modules/vpc/aws","versions":["6.7.3"],"providers":["hashicorp/aws"],"inputs":[],"outputs":[]}`), "must be a name like"},
		"reserved":          {put("modules/aws/vpc.json", `{"id":"aws-vpc","kind":"Defaults","title":"t","description":"d","source":"terraform-aws-modules/vpc/aws","versions":["6.7.3"],"providers":["hashicorp/aws"],"inputs":[],"outputs":[]}`), "reserved"},
		"dup":               {put("modules/aws/vpc2.yaml", "id: aws-vpc2\nkind: VPC\ntitle: t\ndescription: d\nsource: terraform-aws-modules/vpc/aws\nversions: [6.7.3]\nproviders: [hashicorp/aws]\ninputs: []\noutputs: []\n"), "already used"},
		"sensitive default": {put("modules/aws/db.yaml", "id: aws-db\nkind: DB\ntitle: t\ndescription: d\nsource: terraform-aws-modules/rds/aws\nversions: [6.7.3]\nproviders: [hashicorp/aws]\ninputs:\n  - {name: password, type: string, sensitive: true, default: x}\noutputs: []\n"), "cannot have a default"},
	} {
		err := layout(t, c.mutate)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want error containing %q, got %v", name, c.want, err)
		}
	}
}
