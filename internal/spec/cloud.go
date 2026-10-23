package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// Cloud is an environment's cloud integration. It holds identifiers only:
// there is deliberately no field that could carry a key, secret or password,
// and strict decoding rejects any attempt to add one.
//
// Auth modes:
//   - "oidc":    the control plane issues a short-lived signed token per run and the
//     cloud exchanges it for temporary credentials (AWS web identity, GCP
//     workload identity federation, Azure federated credentials).
//   - "ambient": the runner uses the workload identity of where it runs (EKS IRSA /
//     Pod Identity, GKE workload identity, Azure managed identity), optionally
//     assuming a narrower role. Nothing is injected.
type Cloud struct {
	Provider string      `json:"provider"` // none | aws | gcp | azure
	Auth     string      `json:"auth,omitempty"`
	AWS      *AWSCloud   `json:"aws,omitempty"`
	GCP      *GCPCloud   `json:"gcp,omitempty"`
	Azure    *AzureCloud `json:"azure,omitempty"`
}

type AWSCloud struct {
	Region      string `json:"region"`
	RoleARN     string `json:"role_arn"`                // apply role (and plan role unless PlanRoleARN is set)
	PlanRoleARN string `json:"plan_role_arn,omitempty"` // optional read-only role for plans (oidc mode)
	ExternalID  string `json:"external_id,omitempty"`   // ambient mode only
}

type GCPCloud struct {
	ProjectID                string `json:"project_id"`
	Region                   string `json:"region"`
	ServiceAccountEmail      string `json:"service_account_email"`
	PlanServiceAccountEmail  string `json:"plan_service_account_email,omitempty"` // optional read-only account for plans
	WorkloadIdentityProvider string `json:"workload_identity_provider,omitempty"` // oidc mode
}

type AzureCloud struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`
	ClientID       string `json:"client_id"`
	PlanClientID   string `json:"plan_client_id,omitempty"` // optional read-only identity for plans
}

var (
	awsRegionRe = regexp.MustCompile(`^[a-z]{2}(-gov)?-[a-z]+-\d$`)
	roleARNRe   = regexp.MustCompile(`^arn:aws(-us-gov|-cn)?:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	extIDRe     = regexp.MustCompile(`^[A-Za-z0-9+=,.@:/-]{2,1000}$`)
	gcpProjRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpRegionRe = regexp.MustCompile(`^[a-z]+-[a-z]+\d$`)
	gcpSARe     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}@[a-z][a-z0-9-]{4,28}\.iam\.gserviceaccount\.com$`)
	gcpWIPRe    = regexp.MustCompile(`^projects/\d{1,20}/locations/global/workloadIdentityPools/[a-z0-9-]{4,32}/providers/[a-z0-9-]{4,32}$`)
	uuidRe      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func DecodeCloud(b []byte) (*Cloud, error) {
	var c Cloud
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("invalid cloud integration (only identifiers are accepted, never keys or secrets): %w", err)
	}
	return &c, c.Validate()
}

func (c *Cloud) Validate() error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if c.Provider != "none" && c.Auth != "oidc" && c.Auth != "ambient" {
		add(`auth must be "oidc" or "ambient"`)
	}
	set := 0
	for _, p := range []bool{c.AWS != nil, c.GCP != nil, c.Azure != nil} {
		if p {
			set++
		}
	}
	switch c.Provider {
	case "none":
		if set != 0 || c.Auth != "" {
			add(`provider "none" takes no cloud settings`)
		}
	case "aws":
		if c.AWS == nil || set != 1 {
			add("aws settings required (and only aws)")
			break
		}
		if !awsRegionRe.MatchString(c.AWS.Region) {
			add("aws.region is invalid")
		}
		if !roleARNRe.MatchString(c.AWS.RoleARN) {
			add("aws.role_arn must be an IAM role ARN")
		}
		if c.AWS.PlanRoleARN != "" && (c.Auth != "oidc" || !roleARNRe.MatchString(c.AWS.PlanRoleARN)) {
			add("aws.plan_role_arn must be an IAM role ARN and needs oidc auth")
		}
		if c.AWS.ExternalID != "" && (c.Auth != "ambient" || !extIDRe.MatchString(c.AWS.ExternalID)) {
			add("aws.external_id is only valid in ambient mode and must be 2-1000 safe characters")
		}
	case "gcp":
		if c.GCP == nil || set != 1 {
			add("gcp settings required (and only gcp)")
			break
		}
		if !gcpProjRe.MatchString(c.GCP.ProjectID) || !gcpRegionRe.MatchString(c.GCP.Region) {
			add("gcp.project_id or gcp.region is invalid")
		}
		if !gcpSARe.MatchString(c.GCP.ServiceAccountEmail) {
			add("gcp.service_account_email must be a service account email")
		}
		if c.GCP.PlanServiceAccountEmail != "" && !gcpSARe.MatchString(c.GCP.PlanServiceAccountEmail) {
			add("gcp.plan_service_account_email must be a service account email")
		}
		if c.Auth == "oidc" && !gcpWIPRe.MatchString(c.GCP.WorkloadIdentityProvider) {
			add("gcp.workload_identity_provider must be projects/N/locations/global/workloadIdentityPools/P/providers/X")
		}
	case "azure":
		if c.Azure == nil || set != 1 {
			add("azure settings required (and only azure)")
			break
		}
		for k, v := range map[string]string{"tenant_id": c.Azure.TenantID, "subscription_id": c.Azure.SubscriptionID, "client_id": c.Azure.ClientID, "plan_client_id": c.Azure.PlanClientID} {
			if k == "plan_client_id" && v == "" {
				continue
			}
			if !uuidRe.MatchString(v) {
				add("azure.%s must be a UUID", k)
			}
		}
	default:
		add(`provider must be one of none, aws, gcp, azure`)
	}
	return errors.Join(errs...)
}

// Audience is the "aud" claim for the run's OIDC token, as each cloud expects.
func (c *Cloud) Audience() string {
	switch c.Provider {
	case "aws":
		return "sts.amazonaws.com"
	case "gcp":
		return "//iam.googleapis.com/" + c.GCP.WorkloadIdentityProvider
	case "azure":
		return "api://AzureADTokenExchange"
	}
	return ""
}

// NeedsOIDCToken reports whether runs in this environment need a platform-issued token.
func (c *Cloud) NeedsOIDCToken() bool { return c.Provider != "none" && c.Auth == "oidc" }

// PhaseCredentials returns the environment variables and files a runner sets
// for one phase of a run. Identities live here, not in the generated config,
// because a saved plan carries its provider configuration into the apply: this
// is what lets plans run as a read-only identity and applies as the deployer.
// File paths are relative to the run's working directory.
func (c *Cloud) PhaseCredentials(stack, phase string) (map[string]string, map[string][]byte) {
	env, files := map[string]string{}, map[string][]byte{}
	pick := func(apply, plan string) string {
		if phase == "plan" && plan != "" {
			return plan
		}
		return apply
	}
	session := "pravaha-" + phase + "-" + stack
	if len(session) > 64 {
		session = session[:64]
	}
	switch c.Provider {
	case "aws":
		if c.Auth == "oidc" {
			env["AWS_ROLE_ARN"] = pick(c.AWS.RoleARN, c.AWS.PlanRoleARN)
			env["AWS_WEB_IDENTITY_TOKEN_FILE"] = TokenFile
			env["AWS_ROLE_SESSION_NAME"] = session
		}
	case "gcp":
		sa := pick(c.GCP.ServiceAccountEmail, c.GCP.PlanServiceAccountEmail)
		if c.Auth == "oidc" {
			ext := map[string]any{
				"type":                              "external_account",
				"audience":                          c.Audience(),
				"subject_token_type":                "urn:ietf:params:oauth:token-type:jwt",
				"token_url":                         "https://sts.googleapis.com/v1/token",
				"credential_source":                 map[string]any{"file": TokenFile},
				"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + sa + ":generateAccessToken",
			}
			b, _ := json.MarshalIndent(ext, "", "  ")
			files[GCPExternalFile] = b
		} else {
			env["GOOGLE_IMPERSONATE_SERVICE_ACCOUNT"] = sa
		}
	case "azure":
		env["ARM_CLIENT_ID"] = pick(c.Azure.ClientID, c.Azure.PlanClientID)
	}
	return env, files
}

// PhaseEnvAllowed is the only environment a control plane may hand a runner.
var PhaseEnvAllowed = map[string]bool{
	"AWS_ROLE_ARN": true, "AWS_WEB_IDENTITY_TOKEN_FILE": true, "AWS_ROLE_SESSION_NAME": true,
	"GOOGLE_IMPERSONATE_SERVICE_ACCOUNT": true, "ARM_CLIENT_ID": true,
}
