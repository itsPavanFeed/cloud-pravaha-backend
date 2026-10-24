package spec

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

func testCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	f := func(v float64) *float64 { return &v }
	c, err := catalog.New([]*catalog.Module{
		{ID: "azure-naming", Source: "Azure/naming/azurerm", Versions: []string{"0.4.3", "0.4.4"}, Providers: []string{"hashicorp/random"},
			Inputs: []*catalog.Input{
				{Name: "suffix", Type: "list(string)", ItemPattern: "^[a-z0-9]{1,10}$", MaxItems: 3},
				{Name: "unique-length", Type: "number", Min: f(1), Max: f(8)},
			},
			Outputs: []string{"storage_account", "resource_group"}},
		{ID: "aws-vpc", Source: "terraform-aws-modules/vpc/aws", Versions: []string{"6.7.3"}, Cloud: "aws", Providers: []string{"hashicorp/aws"},
			Inputs:   []*catalog.Input{{Name: "name", Type: "string", Required: true, Pattern: "^[a-z0-9-]{1,48}$"}, {Name: "tags", Type: "map(string)"}},
			Enforced: map[string]any{"enable_flow_log": true},
			Outputs:  []string{"vpc_id"}},
		{ID: "aws-sg", Source: "terraform-aws-modules/security-group/aws", Versions: []string{"6.0.0"}, Cloud: "aws", Providers: []string{"hashicorp/aws"},
			Inputs:  []*catalog.Input{{Name: "vpc_id", Type: "string", Required: true, Pattern: "^vpc-[0-9a-f]{8,17}$"}, {Name: "ingress_rules", Type: "json"}},
			Outputs: []string{"id"}},
	}, []catalog.Provider{{Source: "hashicorp/random", Version: "3.9.1"}, {Source: "hashicorp/aws", Version: "6.70.0", Cloud: "aws"}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustDecode(t *testing.T, s string) *Stack {
	t.Helper()
	st, err := Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestValidStackGeneratesPinnedConfig(t *testing.T) {
	cat := testCatalog(t)
	st := mustDecode(t, `{"modules":[{"name":"naming","module":"azure-naming","inputs":{"suffix":["demo"],"unique-length":5}}],
		"outputs":[{"name":"sa","module":"naming","output":"storage_account"}]}`)
	gen, err := st.Generate(cat, GenerateInput{StackName: "demo", Environment: "dev", Cloud: &Cloud{Provider: "none"}, TofuVersion: "1.13.2"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(gen.Files[ConfigFile], &cfg)
	mod := cfg["module"].(map[string]any)["naming"].(map[string]any)
	if mod["source"] != "registry.opentofu.org/Azure/naming/azurerm" || mod["version"] != "0.4.4" {
		t.Fatalf("module not pinned to the latest approved version: %v", mod)
	}
	rp := cfg["terraform"].(map[string]any)["required_providers"].(map[string]any)["random"].(map[string]any)
	if rp["version"] != "3.9.1" {
		t.Fatalf("provider not pinned: %v", rp)
	}
	if cfg["terraform"].(map[string]any)["required_version"] != "= 1.13.2" {
		t.Fatal("engine version not pinned")
	}
	if _, ok := cfg["terraform"].(map[string]any)["backend"].(map[string]any)["http"]; !ok {
		t.Fatal("state must go to the control plane HTTP backend")
	}
}

func TestEnforcedBaselineAndReferences(t *testing.T) {
	cat := testCatalog(t)
	st := mustDecode(t, `{"modules":[
		{"name":"vpc","module":"aws-vpc","inputs":{"name":"main"}},
		{"name":"sg","module":"aws-sg","inputs":{"vpc_id":{"$ref":"vpc.vpc_id"}}}]}`)
	cloud := &Cloud{Provider: "aws", Auth: "oidc", AWS: &AWSCloud{Region: "eu-west-1", RoleARN: "arn:aws:iam::123456789012:role/pravaha"}}
	gen, err := st.Generate(cat, GenerateInput{StackName: "net", Environment: "prod", Cloud: cloud, TofuVersion: "1.13.2"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(gen.Files[ConfigFile])
	for _, want := range []string{`"enable_flow_log": true`, `"vpc_id": "${module.vpc.vpc_id}"`, `"skip_metadata_api_check": true`, `"managed-by": "cloud-pravaha"`} {
		if !strings.Contains(s, want) {
			t.Errorf("generated config is missing %s\n%s", want, s)
		}
	}
	for _, bad := range []string{"access_key", "secret_key", "profile", "arn:aws:iam"} {
		if strings.Contains(s, bad) {
			t.Errorf("generated config must never contain %q", bad)
		}
	}
}

// Every case here is an attempt to run something other than a pinned public module.
func TestRejectsAttacks(t *testing.T) {
	cat := testCatalog(t)
	cases := map[string]string{
		"unknown module":            `{"modules":[{"name":"x","module":"my-custom-module"}]}`,
		"unapproved version":        `{"modules":[{"name":"x","module":"azure-naming","version":"0.1.0"}]}`,
		"version range":             `{"modules":[{"name":"x","module":"azure-naming","version":">= 0.4"}]}`,
		"raw git source field":      `{"modules":[{"name":"x","module":"azure-naming","source":"git::https://evil/x"}]}`,
		"interpolation":             `{"modules":[{"name":"x","module":"azure-naming","inputs":{"suffix":["${file(\"/etc/passwd\")}"]}}]}`,
		"template directive":        `{"modules":[{"name":"x","module":"azure-naming","inputs":{"suffix":["%{if true}x%{endif}"]}}]}`,
		"interpolation in json":     `{"modules":[{"name":"v","module":"aws-vpc","inputs":{"name":"a"}},{"name":"x","module":"aws-sg","inputs":{"vpc_id":"vpc-0123456789abcdef0","ingress_rules":{"a":{"description":"${local.x}"}}}}]}`,
		"interpolation in json key": `{"modules":[{"name":"v","module":"aws-vpc","inputs":{"name":"a"}},{"name":"x","module":"aws-sg","inputs":{"vpc_id":"vpc-0123456789abcdef0","ingress_rules":{"${x}":{}}}}]}`,
		"unknown input":             `{"modules":[{"name":"x","module":"azure-naming","inputs":{"providers":{"random":"random.evil"}}}]}`,
		"override enforced":         `{"modules":[{"name":"x","module":"aws-vpc","inputs":{"name":"a","enable_flow_log":false}}]}`,
		"missing required":          `{"modules":[{"name":"x","module":"aws-vpc"}]}`,
		"pattern violation":         `{"modules":[{"name":"x","module":"aws-vpc","inputs":{"name":"UPPER_case!"}}]}`,
		"out of range":              `{"modules":[{"name":"x","module":"azure-naming","inputs":{"unique-length":99}}]}`,
		"wrong type":                `{"modules":[{"name":"x","module":"azure-naming","inputs":{"unique-length":"5"}}]}`,
		"ref to unknown":            `{"modules":[{"name":"x","module":"aws-sg","inputs":{"vpc_id":{"$ref":"nope.vpc_id"}}}]}`,
		"ref expression injection":  `{"modules":[{"name":"v","module":"aws-vpc","inputs":{"name":"a"}},{"name":"x","module":"aws-sg","inputs":{"vpc_id":{"$ref":"v.vpc_id}${file(\"x\")"}}}]}`,
		"ref unapproved output":     `{"modules":[{"name":"v","module":"aws-vpc","inputs":{"name":"a"}},{"name":"x","module":"aws-sg","inputs":{"vpc_id":{"$ref":"v.secret"}}}]}`,
		"self ref":                  `{"modules":[{"name":"x","module":"aws-sg","inputs":{"vpc_id":{"$ref":"x.id"}}}]}`,
		"nested ref":                `{"modules":[{"name":"v","module":"aws-vpc","inputs":{"name":"a"}},{"name":"x","module":"aws-sg","inputs":{"vpc_id":"vpc-0123456789abcdef0","ingress_rules":{"a":{"$ref":"v.vpc_id"}}}}]}`,
		"cloud mismatch":            `{"modules":[{"name":"x","module":"aws-vpc","inputs":{"name":"a"}}]}`,
		"bad instance name":         `{"modules":[{"name":"Robert'); DROP","module":"azure-naming"}]}`,
		"duplicate instance":        `{"modules":[{"name":"x","module":"azure-naming"},{"name":"x","module":"azure-naming"}]}`,
		"output not approved":       `{"modules":[{"name":"x","module":"azure-naming"}],"outputs":[{"name":"o","module":"x","output":"everything"}]}`,
		"no modules":                `{"modules":[]}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			st, err := Decode([]byte(raw))
			if err != nil {
				return // strict decoding rejected it
			}
			cloud := "none"
			if name != "cloud mismatch" && strings.Contains(raw, "aws-") {
				cloud = "aws"
			}
			if err := st.Validate(cat, cloud); err == nil {
				t.Fatalf("expected rejection for %s", raw)
			}
		})
	}
}

func TestCloudRejectsSecrets(t *testing.T) {
	bad := []string{
		`{"provider":"aws","auth":"oidc","aws":{"region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/x","access_key":"AKIA...","secret_key":"x"}}`,
		`{"provider":"aws","auth":"static","aws":{"region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/x"}}`,
		`{"provider":"aws","auth":"oidc","aws":{"region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/x","endpoints":{"sts":"https://evil"}}}`,
		`{"provider":"gcp","auth":"oidc","gcp":{"project_id":"my-proj-1","region":"europe-west1","service_account_email":"x@y.com","credentials":"{...}"}}`,
		`{"provider":"azure","auth":"oidc","azure":{"tenant_id":"t","subscription_id":"s","client_id":"c","client_secret":"x"}}`,
		`{"provider":"none","aws":{"region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/x"}}`,
	}
	for _, b := range bad {
		if _, err := DecodeCloud([]byte(b)); err == nil {
			t.Errorf("expected rejection: %s", b)
		}
	}
	good := `{"provider":"gcp","auth":"oidc","gcp":{"project_id":"my-proj-1","region":"europe-west1","service_account_email":"deployer@my-proj-1.iam.gserviceaccount.com","workload_identity_provider":"projects/123/locations/global/workloadIdentityPools/pravaha/providers/pravaha"}}`
	if _, err := DecodeCloud([]byte(good)); err != nil {
		t.Fatal(err)
	}
}

func TestConfigHashChangesWithEnvironment(t *testing.T) {
	cat := testCatalog(t)
	st := mustDecode(t, `{"modules":[{"name":"vpc","module":"aws-vpc","inputs":{"name":"main"}}]}`)
	in := func(region string) GenerateInput {
		return GenerateInput{StackName: "n", Environment: "e", TofuVersion: "1.13.2",
			Cloud: &Cloud{Provider: "aws", Auth: "oidc", AWS: &AWSCloud{Region: region, RoleARN: "arn:aws:iam::123456789012:role/r"}}}
	}
	a, _ := st.Generate(cat, in("eu-west-1"))
	b, _ := st.Generate(cat, in("eu-west-1"))
	c, _ := st.Generate(cat, in("us-east-1"))
	if a.Hash != b.Hash || a.Hash == c.Hash {
		t.Fatal("config hash must be deterministic and change when the environment changes")
	}
}

func TestPhaseCredentials(t *testing.T) {
	c, err := DecodeCloud([]byte(`{"provider":"aws","auth":"oidc","aws":{"region":"eu-west-1","role_arn":"arn:aws:iam::123456789012:role/deployer","plan_role_arn":"arn:aws:iam::123456789012:role/reader"}}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, _ := c.PhaseCredentials("net", "plan")
	apply, _ := c.PhaseCredentials("net", "apply")
	if plan["AWS_ROLE_ARN"] != "arn:aws:iam::123456789012:role/reader" || apply["AWS_ROLE_ARN"] != "arn:aws:iam::123456789012:role/deployer" ||
		plan["AWS_WEB_IDENTITY_TOKEN_FILE"] != TokenFile {
		t.Fatalf("plan %v apply %v", plan, apply)
	}
	for k := range plan {
		if !PhaseEnvAllowed[k] {
			t.Errorf("%s is not on the runner allowlist", k)
		}
	}
	g, _ := DecodeCloud([]byte(`{"provider":"gcp","auth":"oidc","gcp":{"project_id":"my-proj-1","region":"europe-west1","service_account_email":"deployer@my-proj-1.iam.gserviceaccount.com","plan_service_account_email":"reader@my-proj-1.iam.gserviceaccount.com","workload_identity_provider":"projects/123/locations/global/workloadIdentityPools/pravaha/providers/pravaha"}}`))
	_, pf := g.PhaseCredentials("net", "plan")
	_, af := g.PhaseCredentials("net", "apply")
	if !strings.Contains(string(pf[GCPExternalFile]), "reader@") || !strings.Contains(string(af[GCPExternalFile]), "deployer@") {
		t.Fatal("GCP plan and apply must impersonate different service accounts")
	}
	if _, err := DecodeCloud([]byte(`{"provider":"aws","auth":"ambient","aws":{"region":"eu-west-1","role_arn":"arn:aws:iam::123456789012:role/d","plan_role_arn":"arn:aws:iam::123456789012:role/r"}}`)); err == nil {
		t.Fatal("plan roles need oidc auth on AWS")
	}
}

func TestImports(t *testing.T) {
	cat := testCatalog(t)
	ok := mustDecode(t, `{"modules":[{"name":"vpc","module":"aws-vpc","inputs":{"name":"main"}}],
		"imports":[{"to":"module.vpc.aws_vpc.this[0]","id":"vpc-0123456789abcdef0"},{"to":"module.vpc.module.flow.aws_iam_role.this[\"x\"]","id":"role-x"}]}`)
	cloud := &Cloud{Provider: "aws", Auth: "oidc", AWS: &AWSCloud{Region: "eu-west-1", RoleARN: "arn:aws:iam::123456789012:role/r"}}
	gen, err := ok.Generate(cat, GenerateInput{StackName: "n", Environment: "e", Cloud: cloud, TofuVersion: "1.13.2"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gen.Files[ConfigFile]), `"to": "module.vpc.aws_vpc.this[0]"`) {
		t.Fatal("import block not generated")
	}
	for _, bad := range []string{
		`{"to":"aws_vpc.root","id":"vpc-1"}`,                     // outside any module
		`{"to":"module.nope.aws_vpc.this","id":"vpc-1"}`,         // unknown instance
		`{"to":"module.vpc.aws_vpc.this","id":"${file(\"x\")}"}`, // template in id
		`{"to":"module.vpc.aws_vpc.this","id":"has space"}`,      // not a literal ID
		`{"to":"module.vpc.aws_vpc.this[var.x]","id":"vpc-1"}`,   // expression index
	} {
		st := mustDecode(t, `{"modules":[{"name":"vpc","module":"aws-vpc","inputs":{"name":"main"}}],"imports":[`+bad+`]}`)
		if st.Validate(cat, "aws") == nil {
			t.Errorf("accepted bad import %s", bad)
		}
	}
}

func TestInputIntoEnforcedObject(t *testing.T) {
	c, err := catalog.New([]*catalog.Module{
		{ID: "gcp-sql", Source: "terraform-google-modules/sql-db/google//modules/postgresql", Versions: []string{"28.3.0"}, Cloud: "gcp", Providers: []string{"hashicorp/google"},
			Inputs:   []*catalog.Input{{Name: "private_network", Type: "string", Required: true, Into: "ip_configuration", Pattern: "^projects/[a-z0-9-]+/global/networks/[a-z0-9-]+$"}},
			Enforced: map[string]any{"ip_configuration": map[string]any{"ipv4_enabled": false}}},
	}, []catalog.Provider{{Source: "hashicorp/google", Version: "8.8.0", Cloud: "gcp"}})
	if err != nil {
		t.Fatal(err)
	}
	st := mustDecode(t, `{"modules":[{"name":"db","module":"gcp-sql","inputs":{"private_network":"projects/p-12345/global/networks/n"}}]}`)
	gen, err := st.Generate(c, GenerateInput{StackName: "s", Environment: "e", Cloud: &Cloud{Provider: "gcp", GCP: &GCPCloud{ProjectID: "p-12345", Region: "europe-west1", ServiceAccountEmail: "a@p-12345.iam.gserviceaccount.com"}}, TofuVersion: "1.13.2"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Module map[string]map[string]json.RawMessage `json:"module"`
	}
	json.Unmarshal(gen.Files["main.tf.json"], &cfg)
	db := cfg.Module["db"]
	if _, top := db["private_network"]; top {
		t.Fatal("into input must not be a top-level module argument")
	}
	var ip map[string]any
	json.Unmarshal(db["ip_configuration"], &ip)
	if ip["ipv4_enabled"] != false || ip["private_network"] != "projects/p-12345/global/networks/n" {
		t.Fatalf("ip_configuration = %v", ip)
	}
	if !strings.HasSuffix(string(db["source"]), `//modules/postgresql"`) {
		t.Fatalf("source = %s", db["source"])
	}
	if !c.ModuleVersionAllowed("terraform-google-modules/sql-db/google", "28.3.0") {
		t.Fatal("the package address of a submodule entry should be allowed")
	}
	// The enforced object cannot be overridden through an into input either.
	_, err = catalog.New([]*catalog.Module{{ID: "x", Source: "a/b/google", Versions: []string{"1.0.0"}, Cloud: "gcp", Providers: []string{"hashicorp/google"},
		Inputs:   []*catalog.Input{{Name: "ipv4_enabled", Type: "bool", Into: "ip_configuration"}},
		Enforced: map[string]any{"ip_configuration": map[string]any{"ipv4_enabled": false}}}},
		[]catalog.Provider{{Source: "hashicorp/google", Version: "8.8.0", Cloud: "gcp"}})
	if err == nil || !strings.Contains(err.Error(), "override") {
		t.Fatalf("want override error, got %v", err)
	}
}

func TestOrganisationLabels(t *testing.T) {
	l := Labels(GenerateInput{Tenant: "acme", Entity: "Retail Co", BU: "payments", Environment: "payments-prod", StackName: "api"})
	want := map[string]string{"managed-by": "cloud-pravaha", "pravaha-tenant": "acme", "pravaha-entity": "retail-co", "pravaha-bu": "payments", "pravaha-environment": "payments-prod", "pravaha-stack": "api"}
	for k, v := range want {
		if l[k] != v {
			t.Fatalf("%s = %q, want %q (all: %v)", k, l[k], v, l)
		}
	}
	c, err := catalog.New([]*catalog.Module{
		{ID: "azure-thing", Source: "Azure/thing/azurerm", Versions: []string{"1.0.0"}, Cloud: "azure", Providers: []string{"Azure/azapi"},
			Inputs: []*catalog.Input{{Name: "name", Type: "string"}, {Name: "tags", Type: "map(string)"}}},
	}, []catalog.Provider{{Source: "Azure/azapi", Version: "2.13.0", Cloud: "azure"}})
	if err != nil {
		t.Fatal(err)
	}
	st := mustDecode(t, `{"modules":[{"name":"x","module":"azure-thing","inputs":{"name":"n","tags":{"team":"pay","pravaha-bu":"spoofed"}}}]}`)
	gen, err := st.Generate(c, GenerateInput{StackName: "api", Environment: "payments-prod", Tenant: "acme", Entity: "retail", BU: "payments",
		Cloud: &Cloud{Provider: "azure", Auth: "oidc", Azure: &AzureCloud{TenantID: "00000000-0000-0000-0000-000000000001", SubscriptionID: "00000000-0000-0000-0000-000000000002", ClientID: "00000000-0000-0000-0000-000000000003"}}, TofuVersion: "1.13.2"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Module map[string]struct {
			Tags map[string]string `json:"tags"`
		} `json:"module"`
	}
	json.Unmarshal(gen.Files["main.tf.json"], &cfg)
	tags := cfg.Module["x"].Tags
	if tags["team"] != "pay" || tags["pravaha-bu"] != "payments" || tags["pravaha-entity"] != "retail" {
		t.Fatalf("azure tags = %v (user tags kept, platform labels win)", tags)
	}
}
