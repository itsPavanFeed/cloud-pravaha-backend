// Package policy evaluates a plan before anyone can approve it.
//
// The runner sends a redacted summary of `tofu show -json` (addresses, types,
// actions and non-sensitive planned values). Hard violations block the run;
// advisory ones are shown to the approver.
package policy

import (
	"fmt"
	"strings"
)

type ResourceChange struct {
	Address string         `json:"address"`
	Type    string         `json:"type"`
	Actions []string       `json:"actions"`
	After   map[string]any `json:"after,omitempty"` // sensitive and unknown values removed
}

type Summary struct {
	Add       int              `json:"add"`
	Change    int              `json:"change"`
	Destroy   int              `json:"destroy"`
	Replace   int              `json:"replace"`
	Imports   int              `json:"imports,omitempty"` // existing resources adopted into state
	Resources []ResourceChange `json:"resources"`
	Outputs   []string         `json:"outputs,omitempty"`
}

func (s *Summary) HasChanges() bool { return s.Add+s.Change+s.Destroy+s.Replace > 0 }

type Violation struct {
	Rule    string `json:"rule"`
	Level   string `json:"level"` // hard | advisory
	Address string `json:"address,omitempty"`
	Message string `json:"message"`
}

type Result struct {
	Passed     bool        `json:"passed"`
	Violations []Violation `json:"violations"`
}

// Limits come from the environment.
type Limits struct {
	MaxDestroys  int  // deletes (including replacements) allowed in one run
	AllowDestroy bool // whether destroy runs are allowed at all
	Destroying   bool // this run is a destroy run
}

// Resource types that create long-lived credentials or public exposure.
var forbiddenTypes = map[string]string{
	"aws_iam_access_key":          "creates a static AWS access key",
	"aws_iam_user_login_profile":  "creates a console password",
	"aws_iam_user":                "IAM users are not allowed; use roles",
	"google_service_account_key":  "creates a static GCP service account key",
	"google_storage_bucket_acl":   "legacy ACLs can make buckets public",
	"google_storage_hmac_key":     "creates a static HMAC key",
	"azurerm_storage_account_sas": "creates a shared access signature",
}

func Evaluate(s Summary, l Limits) Result {
	var v []Violation
	deletes := s.Destroy + s.Replace
	if l.Destroying && !l.AllowDestroy {
		v = append(v, Violation{Rule: "destroy-disabled", Level: "hard", Message: "destroy runs are disabled for this environment"})
	}
	if !l.Destroying && deletes > l.MaxDestroys {
		v = append(v, Violation{Rule: "destroy-limit", Level: "hard",
			Message: fmt.Sprintf("plan deletes %d resources; this environment allows at most %d per run", deletes, l.MaxDestroys)})
	}
	for _, r := range s.Resources {
		creating := has(r.Actions, "create") || has(r.Actions, "update")
		if why, bad := forbiddenTypes[r.Type]; bad && creating {
			v = append(v, Violation{Rule: "forbidden-resource", Level: "hard", Address: r.Address, Message: r.Type + ": " + why})
		}
		if !creating || r.After == nil {
			continue
		}
		switch r.Type {
		case "aws_vpc_security_group_ingress_rule":
			if r.After["cidr_ipv4"] == "0.0.0.0/0" || r.After["cidr_ipv6"] == "::/0" {
				v = append(v, Violation{Rule: "open-ingress", Level: "hard", Address: r.Address, Message: "ingress from the whole internet is not allowed"})
			}
		case "aws_security_group_rule":
			if r.After["type"] == "ingress" && containsAny(r.After["cidr_blocks"], "0.0.0.0/0") {
				v = append(v, Violation{Rule: "open-ingress", Level: "hard", Address: r.Address, Message: "ingress from the whole internet is not allowed"})
			}
		case "aws_s3_bucket_public_access_block":
			for _, k := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
				if b, ok := r.After[k].(bool); ok && !b {
					v = append(v, Violation{Rule: "s3-public-access", Level: "hard", Address: r.Address, Message: k + " must be true"})
				}
			}
		case "google_storage_bucket":
			if p, ok := r.After["public_access_prevention"].(string); ok && p != "enforced" {
				v = append(v, Violation{Rule: "gcs-public-access", Level: "hard", Address: r.Address, Message: "public_access_prevention must be enforced"})
			}
		case "google_compute_firewall":
			if containsAny(r.After["source_ranges"], "0.0.0.0/0") && r.After["direction"] != "EGRESS" {
				v = append(v, Violation{Rule: "open-ingress", Level: "hard", Address: r.Address, Message: "firewall ingress from 0.0.0.0/0 is not allowed"})
			}
		}
		if strings.HasPrefix(r.Type, "aws_") && r.After["tags_all"] == nil && r.After["tags"] == nil && taggable(r.Type) {
			v = append(v, Violation{Rule: "tags", Level: "advisory", Address: r.Address, Message: "resource has no tags"})
		}
	}
	passed := true
	for _, x := range v {
		if x.Level == "hard" {
			passed = false
		}
	}
	return Result{Passed: passed, Violations: v}
}

func taggable(t string) bool {
	switch t {
	case "aws_vpc", "aws_subnet", "aws_s3_bucket", "aws_security_group", "aws_instance", "aws_nat_gateway", "aws_internet_gateway":
		return true
	}
	return false
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsAny(v any, want string) bool {
	xs, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range xs {
		if s, ok := x.(string); ok && s == want {
			return true
		}
	}
	return false
}
