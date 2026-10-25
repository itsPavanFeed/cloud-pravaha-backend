package spec

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

func kindCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	c, err := catalog.New([]*catalog.Module{
		{ID: "aws-s3-bucket", Kind: "S3Bucket", Source: "terraform-aws-modules/s3-bucket/aws", Versions: []string{"5.16.0", "5.17.0"}, Cloud: "aws", Providers: []string{"hashicorp/aws"},
			Inputs: []*catalog.Input{
				{Name: "bucket", Type: "string", Required: true},
				{Name: "force_destroy", Type: "bool", Default: false},
				{Name: "tags", Type: "map(string)"},
				{Name: "kms_key", Type: "string"},
			},
			Enforced: map[string]any{"block_public_acls": true}, Outputs: []string{"s3_bucket_arn"}},
		{ID: "aws-rds", Kind: "RDSDatabase", Source: "terraform-aws-modules/rds/aws", Versions: []string{"7.0.0"}, Cloud: "aws", Providers: []string{"hashicorp/aws"},
			Inputs: []*catalog.Input{{Name: "identifier", Type: "string", Required: true}, {Name: "password", Type: "string", Sensitive: true}, {Name: "instance_class", Type: "string"}}},
	}, []catalog.Provider{{Source: "hashicorp/aws", Version: "6.70.0", Cloud: "aws"}, {Source: "hashicorp/vault", Version: "5.13.0"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var awsOIDC = &Cloud{Provider: "aws", Auth: "oidc", AWS: &AWSCloud{Region: "eu-west-1", RoleARN: "arn:aws:iam::123456789012:role/r"}}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestKindsAndLayeredDefaults(t *testing.T) {
	cat := kindCatalog(t)
	ov := &catalog.Overlay{Tenant: "acme", Kinds: map[string]*catalog.Defaults{"S3Bucket": {
		Target: "S3Bucket", Version: "5.16.0",
		Spec:  map[string]json.RawMessage{"force_destroy": raw("true"), "tags": raw(`{"cost-centre":"cc-1","team":"platform"}`)},
		Tiers: map[string]map[string]json.RawMessage{"prod": {"force_destroy": raw("false")}},
	}}}
	if err := ValidateOverlay(cat, ov); err != nil {
		t.Fatal(err)
	}
	st := mustDecode(t, `{"modules":[{"name":"orders","kind":"S3Bucket","inputs":{"bucket":"acme-orders","tags":{"team":"payments"}}}]}`)
	gen := func(tier string) map[string]string {
		g, err := st.Generate(cat, GenerateInput{StackName: "s", Environment: "e", Tier: tier, Cloud: awsOIDC, TofuVersion: "1.13.2", Defaults: ov})
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("SHOW_HCL") != "" {
			t.Logf("\n%s", g.Files[ConfigFile])
		}
		return block(t, g.Files[ConfigFile], "module orders")
	}
	dev := gen("nonprod")
	if dev["version"] != `"5.16.0"` {
		t.Errorf("tenant default version not used: %v", dev["version"])
	}
	if dev["force_destroy"] != "true" {
		t.Errorf("tenant default not applied: %v", dev)
	}
	tags := literal(t, dev["tags"])
	if tags.GetAttr("team").AsString() != "payments" || tags.GetAttr("cost-centre").AsString() != "cc-1" {
		t.Errorf("tags must merge, contract winning: %v", tags)
	}
	if prod := gen("prod"); prod["force_destroy"] != "false" {
		t.Errorf("tier default not applied: %v", prod)
	}
	// Defaults cannot touch the baseline, unknown inputs or other resources.
	for name, bad := range map[string]map[string]json.RawMessage{
		"enforced": {"block_public_acls": raw("false")},
		"unknown":  {"acl": raw(`"public-read"`)},
		"ref":      {"kms_key": raw(`{"$ref":"key.arn"}`)},
		"template": {"bucket": raw(`"${file(\"x\")}"`)},
	} {
		ov := &catalog.Overlay{Tenant: "acme", Kinds: map[string]*catalog.Defaults{"S3Bucket": {Target: "S3Bucket", Spec: bad}}}
		if ValidateOverlay(cat, ov) == nil {
			t.Errorf("overlay %s accepted", name)
		}
	}
	// A required input can come from a default.
	ov.Kinds["S3Bucket"].Spec["bucket"] = raw(`"acme-default"`)
	if err := mustDecode(t, `{"modules":[{"name":"b","kind":"S3Bucket"}]}`).ValidateWith(cat, "aws", Options{Defaults: ov}); err != nil {
		t.Errorf("required input satisfied by default rejected: %v", err)
	}
	if mustDecode(t, `{"modules":[{"name":"b","kind":"S3Buckt"}]}`).Validate(cat, "aws") == nil {
		t.Error("unknown kind accepted")
	}
	if mustDecode(t, `{"modules":[{"name":"b","kind":"RDSDatabase","module":"aws-s3-bucket"}]}`).Validate(cat, "aws") == nil {
		t.Error("kind and module disagreeing accepted")
	}
}

func TestSecretReferences(t *testing.T) {
	cat := kindCatalog(t)
	st := mustDecode(t, `{"modules":[{"name":"db","kind":"RDSDatabase","inputs":{"identifier":"orders","password":{"$secret":"vault://kv/orders/db#password"}}}]}`)
	in := GenerateInput{StackName: "s", Environment: "e", Cloud: awsOIDC, TofuVersion: "1.13.2"}
	if _, err := st.Generate(cat, in); err == nil || !strings.Contains(err.Error(), "secret store") {
		t.Fatalf("secrets without a configured store: %v", err)
	}
	in.Vault = &Vault{Address: "https://bao.acme.internal:8200", Role: "pravaha"}
	g, err := st.Generate(cat, in)
	if err != nil {
		t.Fatal(err)
	}
	cfg := g.Files[ConfigFile]
	if os.Getenv("SHOW_HCL") != "" {
		t.Logf("\n%s", cfg)
	}
	if !g.Secrets || !strings.Contains(strings.Join(g.Providers, ","), "hashicorp/vault") {
		t.Fatalf("vault provider not added: %+v", g.Providers)
	}
	pw := block(t, cfg, "module db")["password"]
	if !strings.HasPrefix(pw, "data.vault_kv_secret_v2.secret_") || !strings.HasSuffix(pw, `.data["password"]`) {
		t.Fatalf("password = %s", pw)
	}
	login := block(t, cfg, "provider vault", "auth_login_jwt")
	if login["jwt"] != `file(".pravaha/vault-token")` || login["role"] != `"pravaha"` || login["mount"] != `"jwt"` {
		t.Fatalf("vault login = %v", login)
	}
	for name, bad := range map[string]string{
		"literal sensitive":  `{"identifier":"o","password":"hunter2-hunter2"}`,
		"traversal":          `{"identifier":"o","password":{"$secret":"vault://kv/../sys#x"}}`,
		"other scheme":       `{"identifier":"o","password":{"$secret":"aws-sm://x#y"}}`,
		"injection":          `{"identifier":"o","password":{"$secret":"vault://kv/a#k\"]}${file(\"x\")"}}`,
		"extra keys":         `{"identifier":"o","password":{"$secret":"vault://kv/a#k","x":1}}`,
		"credential literal": `{"identifier":"AKIAABCDEFGHIJKLMNOP"}`,
		"nested":             `{"identifier":"o","instance_class":{"a":{"$secret":"vault://kv/a#k"}}}`,
	} {
		st := mustDecode(t, `{"modules":[{"name":"db","kind":"RDSDatabase","inputs":`+bad+`}]}`)
		if st.Validate(cat, "aws") == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, bad := range []Vault{{Address: "http://bao.example.com", Role: "r"}, {Address: "https://bao", Role: ""}, {Address: "https://u:p@bao", Role: "r"}} {
		if bad.Validate() == nil {
			t.Errorf("vault config %+v accepted", bad)
		}
	}
}

func TestRendererEscapesTemplates(t *testing.T) {
	b, err := renderHCL("", []*hblock{(&hblock{typ: "module", labels: []string{"x"}}).set("a", "${file(\"/etc/passwd\")}").set("b", map[string]any{"%{if}": "x"})})
	if err != nil {
		t.Fatal(err)
	}
	attrs := block(t, b, "module x")
	if literal(t, attrs["a"]).AsString() != `${file("/etc/passwd")}` {
		t.Fatalf("template was not escaped: %s", b)
	}
	if !strings.Contains(string(b), "$${") || !strings.Contains(string(b), "%%{") {
		t.Fatalf("expected escaped sequences:\n%s", b)
	}
}

func TestRealTenantDefaults(t *testing.T) {
	cat, err := catalog.Load("../../../cloud-pravaha-modules/catalog")
	if err != nil {
		t.Skipf("modules repo not available: %v", err)
	}
	ov, err := catalog.LoadOverlay(os.DirFS("../../../cloud-pravaha-modules"), "tenants/acme", "acme", cat)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOverlay(cat, ov); err != nil {
		t.Fatal(err)
	}
	if ov.For("AzureNaming") == nil {
		t.Fatal("acme's AzureNaming defaults missing")
	}
}
