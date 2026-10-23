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
	Cloud       *Cloud
	TofuVersion string // exact engine version runs must use
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
		for k, raw := range m.Inputs {
			v, _ := decodeAny(raw)
			if ref, ok, _ := asRef(v); ok {
				p := refRe.FindStringSubmatch(ref)
				block[k] = fmt.Sprintf("${module.%s.%s}", p[1], p[2])
				continue
			}
			block[k] = json.RawMessage(raw)
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
func providerConfig(in GenerateInput, used map[string]catalog.Provider, files map[string][]byte) (map[string]any, error) {
	c := in.Cloud
	out := map[string]any{}
	has := func(src string) bool { _, ok := used[src]; return ok }
	session := "pravaha-" + in.StackName
	if len(session) > 64 {
		session = session[:64]
	}
	tags := map[string]string{
		"managed-by":          "cloud-pravaha",
		"pravaha-stack":       in.StackName,
		"pravaha-environment": in.Environment,
	}

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
			p["assume_role_with_web_identity"] = map[string]any{
				"role_arn":                c.AWS.RoleARN,
				"session_name":            session,
				"web_identity_token_file": TokenFile,
				"duration":                "1h",
			}
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
			"default_labels":                  map[string]string{"managed-by": "cloud-pravaha", "pravaha-stack": in.StackName},
			"add_terraform_attribution_label": true,
		}
		if c.Auth == "oidc" {
			ext := map[string]any{
				"type":                              "external_account",
				"audience":                          c.Audience(),
				"subject_token_type":                "urn:ietf:params:oauth:token-type:jwt",
				"token_url":                         "https://sts.googleapis.com/v1/token",
				"credential_source":                 map[string]any{"file": TokenFile},
				"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + c.GCP.ServiceAccountEmail + ":generateAccessToken",
			}
			b, _ := json.MarshalIndent(ext, "", "  ")
			files[GCPExternalFile] = b
			p["credentials"] = GCPExternalFile
		} else {
			p["impersonate_service_account"] = c.GCP.ServiceAccountEmail
		}
		for _, src := range []string{"hashicorp/google", "hashicorp/google-beta"} {
			if has(src) {
				out[src[strings.Index(src, "/")+1:]] = p
			}
		}
	case "azure":
		if has("azure/azapi") {
			p := map[string]any{
				"tenant_id":       c.Azure.TenantID,
				"subscription_id": c.Azure.SubscriptionID,
				"client_id":       c.Azure.ClientID,
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
	// Microsoft's module telemetry provider is always switched off.
	if has("azure/modtm") {
		out["modtm"] = map[string]any{"enabled": false}
	}
	return out, nil
}
