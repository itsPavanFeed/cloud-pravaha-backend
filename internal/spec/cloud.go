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
	Region     string `json:"region"`
	RoleARN    string `json:"role_arn"`
	ExternalID string `json:"external_id,omitempty"` // ambient mode only
}

type GCPCloud struct {
	ProjectID                string `json:"project_id"`
	Region                   string `json:"region"`
	ServiceAccountEmail      string `json:"service_account_email"`
	WorkloadIdentityProvider string `json:"workload_identity_provider,omitempty"` // oidc mode
}

type AzureCloud struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`
	ClientID       string `json:"client_id"`
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
		if c.Auth == "oidc" && !gcpWIPRe.MatchString(c.GCP.WorkloadIdentityProvider) {
			add("gcp.workload_identity_provider must be projects/N/locations/global/workloadIdentityPools/P/providers/X")
		}
	case "azure":
		if c.Azure == nil || set != 1 {
			add("azure settings required (and only azure)")
			break
		}
		for k, v := range map[string]string{"tenant_id": c.Azure.TenantID, "subscription_id": c.Azure.SubscriptionID, "client_id": c.Azure.ClientID} {
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
