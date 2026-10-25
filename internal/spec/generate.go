package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

// Paths inside a run's working directory that generated config refers to.
// The runner writes the short-lived OIDC tokens to TokenFile and VaultTokenFile
// just before each OpenTofu command; nothing secret is ever written into the
// config itself.
const (
	ConfigFile      = "main.tf"
	TokenFile       = ".pravaha/oidc-token"
	VaultTokenFile  = ".pravaha/vault-token"
	GCPExternalFile = ".pravaha/gcp-external-account.json"
	// VendorDir holds the modules of a deployed module release, so plans never
	// download modules from the internet.
	VendorDir = "vendor"
)

type GenerateInput struct {
	StackName   string
	Environment string
	Tier        string // prod | nonprod: picks the tier defaults
	// Where the stack sits in the organisation; used for resource labels.
	Tenant, Entity, BU string
	Cloud              *Cloud
	TofuVersion        string // exact engine version runs must use
	// Defaults is the tenant's defaults overlay (from the deployed module release).
	Defaults *catalog.Overlay
	// Vault is the tenant's secret store; required only when the stack uses secret references.
	Vault *Vault
	// Modules resolves module packages to vendored copies; nil means the public registry.
	Modules ModuleResolver
}

// ModuleResolver maps a registry module at a version to a vendored directory
// (relative to the run directory, e.g. vendor/terraform-aws-modules/vpc/aws/6.7.3)
// and the packages it loads (directory -> SHA-256 of the package files).
type ModuleResolver interface {
	Resolve(source, version string) (dir string, packages map[string]string, ok bool)
}

// Generated is a complete, deterministic working directory for one stack.
type Generated struct {
	Files     map[string][]byte `json:"files"`
	Providers []string          `json:"providers"` // allowed provider sources, for the runner's install policy
	Modules   []string          `json:"modules"`   // catalog module sources used
	// Vendored lists the module packages runs need (directory -> SHA-256).
	// Their checksums are part of the config, so a plan is stale only when
	// the modules this stack loads actually change.
	Vendored map[string]string `json:"vendored,omitempty"`
	Secrets   bool              `json:"secrets,omitempty"` // runs need a Vault login token
	Hash      string            `json:"hash"`              // sha256 over every file; changes make saved plans stale
	Spec      json.RawMessage   `json:"-"`                 // the normalized spec (kinds and versions filled in)
}

// Generate produces the OpenTofu configuration for a validated stack.
func (s *Stack) Generate(cat *catalog.Catalog, in GenerateInput) (*Generated, error) {
	opts := Options{Defaults: in.Defaults, Tier: in.Tier}
	if err := s.ValidateWith(cat, in.Cloud.Provider, opts); err != nil {
		return nil, err
	}
	providers := map[string]catalog.Provider{}
	var modules, datas []*hblock
	var sources []string
	vendored := map[string]string{}
	secrets := map[string]*hblock{} // data source per secret path
	secretExpr := func(ref string) expr {
		p := secretRe.FindStringSubmatch(ref)
		sum := sha256.Sum256([]byte(p[1] + "/" + p[2]))
		name := "secret_" + hex.EncodeToString(sum[:5])
		if secrets[name] == nil {
			d := &hblock{typ: "data", labels: []string{"vault_kv_secret_v2", name}, comment: "secret reference vault://" + p[1] + "/" + p[2]}
			d.set("mount", p[1]).set("name", p[2])
			secrets[name] = d
		}
		return traversal("data", "vault_kv_secret_v2", name, "data", "["+p[3]+"]")
	}
	// literal turns a stored value into what the config writes: references and
	// secrets become expressions, everything else stays a literal.
	literal := func(raw json.RawMessage) any {
		v, _ := decodeAny(raw)
		if ref, ok, _ := asRef(v); ok {
			p := refRe.FindStringSubmatch(ref)
			return traversal("module", p[1], p[2])
		}
		if sec, ok, _ := asSecret(v); ok {
			return secretExpr(sec)
		}
		return raw
	}

	for _, m := range s.Modules {
		cm := cat.Module(m.Module)
		vals, from := effectiveInputs(cm, m, opts)
		block := &hblock{typ: "module", labels: []string{m.Name}}
		src, ver := catalog.Registry+"/"+cm.Source, m.Version
		if in.Modules != nil {
			dir, pkgs, ok := in.Modules.Resolve(cm.Source, m.Version)
			if !ok {
				return nil, fmt.Errorf("resource %q: %s %s is not in the deployed module release; build and deploy a release that includes it", m.Name, cm.Kind, m.Version)
			}
			src, ver = "./"+dir, ""
			for d, sum := range pkgs {
				vendored[d] = sum
			}
		}
		block.comment = fmt.Sprintf("%s %q (%s %s)", cm.Kind, m.Name, cm.Source, m.Version)
		if len(from) > 0 {
			block.comment += "\ndefaults: " + strings.Join(from, ", ")
		}
		block.set("source", src)
		if ver != "" {
			block.set("version", ver) // exact pin: OpenTofu treats a bare version as "= x.y.z"
		}
		keys := make([]string, 0, len(cm.Enforced))
		for k := range cm.Enforced {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		args := map[string]any{}
		for _, k := range keys {
			args[k] = cm.Enforced[k]
		}
		names := make([]string, 0, len(vals))
		for k := range vals {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			val := literal(vals[k])
			if ci := cm.Input(k); ci != nil && ci.Into != "" {
				obj, _ := args[ci.Into].(map[string]any)
				merged := map[string]any{}
				for ek, ev := range obj {
					merged[ek] = ev
				}
				merged[k] = val
				args[ci.Into] = merged
				continue
			}
			args[k] = val
		}
		if in.Cloud.Provider == "azure" {
			mergeTags(args, cm, Labels(in))
		}
		// Enforced keys first (the baseline), then the resource's own values.
		for _, k := range keys {
			block.set(k, args[k])
		}
		for _, k := range names {
			if ci := cm.Input(k); ci != nil && ci.Into != "" {
				continue
			}
			block.set(k, args[k])
		}
		if _, ok := args["tags"]; ok {
			block.set("tags", args["tags"])
		}
		modules = append(modules, block)
		sources = append(sources, cm.Source)
		for _, p := range cm.Providers {
			pv, _ := cat.Provider(p)
			providers[strings.ToLower(p)] = pv
		}
	}
	if len(secrets) > 0 {
		if in.Vault == nil {
			return nil, fmt.Errorf("the stack uses secret references, but no secret store (OpenBao/Vault) is configured for the tenant; add it under Integrations")
		}
		pv, ok := cat.Provider("hashicorp/vault")
		if !ok {
			return nil, fmt.Errorf("the stack uses secret references, but the hashicorp/vault provider is not allowlisted in the catalog")
		}
		providers["hashicorp/vault"] = pv
		names := make([]string, 0, len(secrets))
		for n := range secrets {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			datas = append(datas, secrets[n])
		}
	}

	tf := &hblock{typ: "terraform"}
	tf.set("required_version", "= "+in.TofuVersion)
	rp := tf.block("required_providers")
	var provSources []string
	locals := map[string]string{}
	for _, p := range providers {
		local := p.Source[strings.Index(p.Source, "/")+1:]
		if other, dup := locals[local]; dup {
			return nil, fmt.Errorf("providers %s and %s collide on local name %q", p.Source, other, local)
		}
		locals[local] = p.Source
		provSources = append(provSources, p.Source)
	}
	sort.Strings(provSources)
	for _, src := range provSources {
		p := providers[strings.ToLower(src)]
		rp.set(src[strings.Index(src, "/")+1:], map[string]any{"source": catalog.Registry + "/" + p.Source, "version": p.Version})
	}
	// The control plane's HTTP state backend. Runners supply the address
	// (TF_HTTP_ADDRESS) from the URL they reach the control plane at, so the
	// generated config and its hash do not depend on network topology.
	be := tf.block("backend", "http")
	be.set("lock_method", "LOCK").set("unlock_method", "UNLOCK").set("retry_max", 3)

	files := map[string][]byte{}
	provs := providerBlocks(in, providers)
	if len(secrets) > 0 {
		provs = append(provs, vaultProvider(in.Vault))
	}

	all := []*hblock{tf}
	all = append(all, provs...)
	all = append(all, datas...)
	all = append(all, modules...)
	for _, im := range s.Imports {
		b := &hblock{typ: "import"}
		b.set("to", addressExpr(im.To)).set("id", im.ID)
		all = append(all, b)
	}
	for _, o := range s.Outputs {
		b := &hblock{typ: "output", labels: []string{o.Name}}
		b.set("value", traversal("module", o.Module, o.Output))
		if o.Sensitive {
			b.set("sensitive", true)
		}
		all = append(all, b)
	}
	header := fmt.Sprintf("Generated by Cloud Pravaha for stack %s in %s (%s/%s). Do not edit.\nOnly approved kinds; enforced baselines are listed first in each module.", in.StackName, in.Environment, in.Entity, in.BU)
	if len(vendored) > 0 {
		header += "\nVendored module packages (runs verify each checksum):"
		for _, d := range sortedKeys(vendored) {
			header += "\n  " + d + " sha256:" + vendored[d]
		}
	}
	main, err := renderHCL(header, all)
	if err != nil {
		return nil, err
	}
	files[ConfigFile] = main
	sort.Strings(sources)

	h := sha256.New()
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(h, "%s\x00%d\x00", n, len(files[n]))
		h.Write(files[n])
	}
	norm, _ := json.Marshal(s)
	if len(vendored) == 0 {
		vendored = nil
	}
	return &Generated{Files: files, Providers: provSources, Modules: sources, Vendored: vendored, Secrets: len(secrets) > 0,
		Hash: hex.EncodeToString(h.Sum(nil)), Spec: norm}, nil
}

// addressExpr writes an import address (already validated by importToRe) as
// a traversal: module.x.module.y["k"].aws_vpc.this[0].
func addressExpr(addr string) expr {
	var t hclwrite.Tokens
	tok := func(typ string, s string) {
		t = append(t, &hclwrite.Token{Type: hclTokenType(typ), Bytes: []byte(s)})
	}
	for i, part := range strings.Split(addr, ".") {
		if i > 0 {
			tok(".", ".")
		}
		name, idx, hasIdx := strings.Cut(part, "[")
		tok("ident", name)
		if hasIdx {
			tok("[", "[")
			tok("raw", strings.TrimSuffix(idx, "]")) // a number or a quoted key, validated
			tok("]", "]")
		}
	}
	return expr(t)
}

// Labels are put on every resource a stack creates: AWS default_tags, GCP
// default_labels, and the tags input of Azure modules. Values follow the
// strictest rules (GCP: lowercase letters, digits, - and _, at most 63).
func Labels(in GenerateInput) map[string]string {
	l := map[string]string{"managed-by": "cloud-pravaha"}
	for k, v := range map[string]string{"pravaha-tenant": in.Tenant, "pravaha-entity": in.Entity, "pravaha-bu": in.BU,
		"pravaha-environment": in.Environment, "pravaha-stack": in.StackName} {
		if v = labelValue(v); v != "" {
			l[k] = v
		}
	}
	return l
}

func labelValue(v string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(v) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
		if b.Len() == 63 {
			break
		}
	}
	return b.String()
}

// providerBlocks builds provider blocks that authenticate only through
// workload identity. Static credentials cannot be expressed: the Cloud type
// has no field for them and no user input reaches a provider block.
func providerBlocks(in GenerateInput, used map[string]catalog.Provider) []*hblock {
	c := in.Cloud
	var out []*hblock
	has := func(src string) bool { _, ok := used[src]; return ok }
	session := "pravaha-" + in.StackName
	if len(session) > 64 {
		session = session[:64]
	}
	tags := Labels(in)

	switch c.Provider {
	case "aws":
		if !has("hashicorp/aws") {
			break
		}
		p := &hblock{typ: "provider", labels: []string{"aws"}}
		p.set("region", c.AWS.Region)
		if c.Auth == "oidc" {
			// Web identity comes from AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE
			// set per phase by the runner (see PhaseCredentials); never fall
			// back to instance metadata credentials.
			p.set("skip_metadata_api_check", true)
		} else {
			ar := p.block("assume_role")
			ar.set("role_arn", c.AWS.RoleARN).set("session_name", session).set("duration", "1h")
			if c.AWS.ExternalID != "" {
				ar.set("external_id", c.AWS.ExternalID)
			}
		}
		p.block("default_tags").set("tags", tags)
		out = append(out, p)
	case "gcp":
		for _, src := range []string{"hashicorp/google", "hashicorp/google-beta"} {
			if !has(src) {
				continue
			}
			p := &hblock{typ: "provider", labels: []string{src[strings.Index(src, "/")+1:]}}
			p.set("project", c.GCP.ProjectID).set("region", c.GCP.Region).set("default_labels", tags).set("add_terraform_attribution_label", true)
			if c.Auth == "oidc" {
				p.set("credentials", GCPExternalFile) // written per phase by the runner
			} // ambient: GOOGLE_IMPERSONATE_SERVICE_ACCOUNT is set per phase
			out = append(out, p)
		}
	case "azure":
		if has("azure/azapi") {
			p := &hblock{typ: "provider", labels: []string{"azapi"}} // client_id comes from ARM_CLIENT_ID per phase
			p.set("tenant_id", c.Azure.TenantID).set("subscription_id", c.Azure.SubscriptionID).set("use_cli", false)
			if c.Auth == "oidc" {
				p.set("use_oidc", true).set("oidc_token_file_path", TokenFile).set("use_msi", false)
			} else {
				p.set("use_msi", true)
			}
			out = append(out, p)
		}
	}
	if c.Provider == "azure" && has("hashicorp/azurerm") {
		p := &hblock{typ: "provider", labels: []string{"azurerm"}} // client_id comes from ARM_CLIENT_ID per phase
		p.set("tenant_id", c.Azure.TenantID).set("subscription_id", c.Azure.SubscriptionID).set("use_cli", false).
			set("resource_provider_registrations", "none")
		if c.Auth == "oidc" {
			p.set("use_oidc", true).set("oidc_token_file_path", TokenFile)
		} else {
			p.set("use_msi", true)
		}
		p.block("features")
		out = append(out, p)
	}
	// Microsoft's module telemetry provider is always switched off.
	if has("azure/modtm") {
		out = append(out, (&hblock{typ: "provider", labels: []string{"modtm"}}).set("enabled", false))
	}
	return out
}

// vaultProvider logs in to OpenBao/Vault with the run's own short-lived
// token (JWT auth), never a stored Vault token. The runner writes the token
// file per phase; the Vault role decides what the run may read.
func vaultProvider(v *Vault) *hblock {
	p := &hblock{typ: "provider", labels: []string{"vault"}, comment: "Secret store: logs in with the run's short-lived OIDC token (JWT auth)."}
	p.set("address", v.Address).set("skip_child_token", true)
	if v.Namespace != "" {
		p.set("namespace", v.Namespace)
	}
	login := p.block("auth_login_jwt")
	login.set("mount", v.mount()).set("role", v.Role).
		set("jwt", call("file", hclwrite.Tokens(mustTokens(VaultTokenFile))))
	return p
}

func mustTokens(s string) hclwrite.Tokens {
	t, _ := valueTokens(s, 0)
	return t
}

// mergeTags adds the platform labels to an Azure module's tags input (Azure has
// no provider-level default tags). Platform labels win over user tags.
func mergeTags(args map[string]any, cm *catalog.Module, labels map[string]string) {
	in := cm.Input("tags")
	if in == nil || in.Type != "map(string)" {
		return
	}
	tags := map[string]any{}
	switch v := args["tags"].(type) {
	case json.RawMessage:
		if json.Unmarshal(v, &tags) != nil {
			return
		}
	case expr: // a module output reference
		lt, _ := valueTokens(labels, 0)
		args["tags"] = call("merge", hclwrite.Tokens(v), lt)
		return
	}
	for k, v := range labels {
		tags[k] = v
	}
	args["tags"] = tags
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
