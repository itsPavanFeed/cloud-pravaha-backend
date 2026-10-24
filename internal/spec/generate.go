package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
)

// Paths inside a run's working directory that generated config refers to.
// The runner writes the short-lived OIDC token to TokenFile just before each
// OpenTofu command; nothing secret is ever written into the config itself.
const (
	ConfigFile      = "main.tf.json"
	TokenFile       = ".pravaha/oidc-token"
	GCPExternalFile = ".pravaha/gcp-external-account.json"
)

type GenerateInput struct {
	StackName   string
	Environment string
	// Where the stack sits in the organisation; used for resource labels.
	Tenant, Entity, BU string
	Cloud              *Cloud
	TofuVersion        string // exact engine version runs must use
}

// Generated is a complete, deterministic working directory for one stack.
type Generated struct {
	Files     map[string][]byte `json:"files"`
	Providers []string          `json:"providers"` // allowed provider sources, for the runner's install policy
	Modules   []string          `json:"modules"`   // catalog module sources used
	Hash      string            `json:"hash"`      // sha256 over every file; changes make saved plans stale
}

// Generate produces the OpenTofu configuration for a validated stack.
func (s *Stack) Generate(cat *catalog.Catalog, in GenerateInput) (*Generated, error) {
	if err := s.Validate(cat, in.Cloud.Provider); err != nil {
		return nil, err
	}
	providers := map[string]catalog.Provider{}
	modules := map[string]any{}
	var sources []string
	for _, m := range s.Modules {
		cm := cat.Module(m.Module)
		block := map[string]any{
			"source":  catalog.Registry + "/" + cm.Source,
			"version": m.Version, // exact pin: OpenTofu treats a bare version as "= x.y.z"
		}
		for k, v := range cm.Enforced {
			block[k] = v
		}
		into := map[string]map[string]any{}
		for k, raw := range m.Inputs {
			var val any = json.RawMessage(raw)
			v, _ := decodeAny(raw)
			if ref, ok, _ := asRef(v); ok {
				p := refRe.FindStringSubmatch(ref)
				val = fmt.Sprintf("${module.%s.%s}", p[1], p[2])
			}
			if in := cm.Input(k); in != nil && in.Into != "" {
				obj := into[in.Into]
				if obj == nil {
					obj = map[string]any{}
					for ek, ev := range cm.Enforced[in.Into].(map[string]any) {
						obj[ek] = ev
					}
					into[in.Into], block[in.Into] = obj, obj
				}
				obj[k] = val
				continue
			}
			block[k] = val
		}
		if in.Cloud.Provider == "azure" {
			mergeTags(block, cm, Labels(in))
		}
		modules[m.Name] = block
		sources = append(sources, cm.Source)
		for _, p := range cm.Providers {
			pv, _ := cat.Provider(p)
			providers[strings.ToLower(p)] = pv
		}
	}

	required := map[string]any{}
	var provSources []string
	for _, p := range providers {
		local := p.Source[strings.Index(p.Source, "/")+1:]
		if _, dup := required[local]; dup {
			return nil, fmt.Errorf("providers %s collide on local name %q", p.Source, local)
		}
		required[local] = map[string]string{
			"source":  catalog.Registry + "/" + p.Source,
			"version": p.Version,
		}
		provSources = append(provSources, p.Source)
	}
	sort.Strings(provSources)
	sort.Strings(sources)

	files := map[string][]byte{}
	provCfg, err := providerConfig(in, providers, files)
	if err != nil {
		return nil, err
	}

	cfg := map[string]any{
		"terraform": map[string]any{
			"required_version":   "= " + in.TofuVersion,
			"required_providers": required,
			// The control plane's HTTP state backend. Runners supply the address
			// (TF_HTTP_ADDRESS) from the URL they reach the control plane at, so the
			// generated config and its hash do not depend on network topology.
			"backend": map[string]any{
				"http": map[string]any{
					"lock_method":   "LOCK",
					"unlock_method": "UNLOCK",
					"retry_max":     3,
				},
			},
		},
		"module": modules,
	}
	if len(provCfg) > 0 {
		cfg["provider"] = provCfg
	}
	if len(s.Imports) > 0 {
		var imps []map[string]string
		for _, im := range s.Imports {
			imps = append(imps, map[string]string{"to": im.To, "id": im.ID})
		}
		cfg["import"] = imps
	}
	if len(s.Outputs) > 0 {
		outs := map[string]any{}
		for _, o := range s.Outputs {
			outs[o.Name] = map[string]any{
				"value":     fmt.Sprintf("${module.%s.%s}", o.Module, o.Output),
				"sensitive": o.Sensitive,
			}
		}
		cfg["output"] = outs
	}
	main, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	files[ConfigFile] = main

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
	return &Generated{Files: files, Providers: provSources, Modules: sources, Hash: hex.EncodeToString(h.Sum(nil))}, nil
}

// providerConfig builds provider blocks that authenticate only through workload
// identity. Static credentials cannot be expressed: the Cloud type has no field
// for them and no user input reaches a provider block.
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

func providerConfig(in GenerateInput, used map[string]catalog.Provider, files map[string][]byte) (map[string]any, error) {
	c := in.Cloud
	out := map[string]any{}
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
		p := map[string]any{
			"region":       c.AWS.Region,
			"default_tags": map[string]any{"tags": tags},
		}
		if c.Auth == "oidc" {
			// Web identity comes from AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE
			// set per phase by the runner (see PhaseCredentials); never fall
			// back to instance metadata credentials.
			p["skip_metadata_api_check"] = true
		} else {
			ar := map[string]any{"role_arn": c.AWS.RoleARN, "session_name": session, "duration": "1h"}
			if c.AWS.ExternalID != "" {
				ar["external_id"] = c.AWS.ExternalID
			}
			p["assume_role"] = ar
		}
		out["aws"] = p
	case "gcp":
		p := map[string]any{
			"project":                         c.GCP.ProjectID,
			"region":                          c.GCP.Region,
			"default_labels":                  tags,
			"add_terraform_attribution_label": true,
		}
		if c.Auth == "oidc" {
			p["credentials"] = GCPExternalFile // written per phase by the runner
		} // ambient: GOOGLE_IMPERSONATE_SERVICE_ACCOUNT is set per phase
		for _, src := range []string{"hashicorp/google", "hashicorp/google-beta"} {
			if has(src) {
				out[src[strings.Index(src, "/")+1:]] = p
			}
		}
	case "azure":
		if has("azure/azapi") {
			p := map[string]any{ // client_id comes from ARM_CLIENT_ID per phase
				"tenant_id":       c.Azure.TenantID,
				"subscription_id": c.Azure.SubscriptionID,
				"use_cli":         false,
			}
			if c.Auth == "oidc" {
				p["use_oidc"] = true
				p["oidc_token_file_path"] = TokenFile
				p["use_msi"] = false
			} else {
				p["use_msi"] = true
			}
			out["azapi"] = p
		}
	}
	if c.Provider == "azure" && has("hashicorp/azurerm") {
		p := map[string]any{ // client_id comes from ARM_CLIENT_ID per phase
			"features":                        []any{map[string]any{}},
			"tenant_id":                       c.Azure.TenantID,
			"subscription_id":                 c.Azure.SubscriptionID,
			"use_cli":                         false,
			"resource_provider_registrations": "none",
		}
		if c.Auth == "oidc" {
			p["use_oidc"] = true
			p["oidc_token_file_path"] = TokenFile
		} else {
			p["use_msi"] = true
		}
		out["azurerm"] = p
	}
	// Microsoft's module telemetry provider is always switched off.
	if has("azure/modtm") {
		out["modtm"] = map[string]any{"enabled": false}
	}
	return out, nil
}

// mergeTags adds the platform labels to an Azure module's tags input (Azure has
// no provider-level default tags). Platform labels win over user tags.
func mergeTags(block map[string]any, cm *catalog.Module, labels map[string]string) {
	in := cm.Input("tags")
	if in == nil || in.Type != "map(string)" {
		return
	}
	tags := map[string]any{}
	switch v := block["tags"].(type) {
	case json.RawMessage:
		if json.Unmarshal(v, &tags) != nil {
			return
		}
	case string: // a module output reference
		lb, _ := json.Marshal(labels)
		block["tags"] = "${merge(" + strings.TrimSuffix(strings.TrimPrefix(v, "${"), "}") + ", " + string(lb) + ")}"
		return
	}
	for k, v := range labels {
		tags[k] = v
	}
	block["tags"] = tags
}
