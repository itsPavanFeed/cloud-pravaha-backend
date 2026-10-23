// Package risk classifies a plan and decides which approvals it needs.
//
//	low     only additions in a non-production environment       manager
//	medium  in-place changes, production, network resources,      manager + finops
//	        or a large change set
//	high    deletions or replacements, destroy runs, identity        manager + finops + security
//	        and access changes, or network exposure in production
package risk

import (
	"fmt"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
)

const (
	Low    = "low"
	Medium = "medium"
	High   = "high"

	largeChange = 25
)

type Result struct {
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
	Steps   []string `json:"required_approvals"`
}

// Tiers an environment can declare.
const (
	TierProd    = "prod"
	TierNonProd = "nonprod"
)

func Classify(s policy.Summary, operation, tier string) Result {
	level := Low
	var reasons []string
	raise := func(to, why string) {
		if rank(to) > rank(level) {
			level = to
		}
		reasons = append(reasons, why)
	}

	if operation == "destroy" {
		raise(High, "destroy run")
	}
	if n := s.Destroy + s.Replace; n > 0 {
		raise(High, fmt.Sprintf("%d resource(s) deleted or replaced", n))
	}
	if tier == TierProd {
		raise(Medium, "production environment")
	}
	if s.Change > 0 {
		raise(Medium, fmt.Sprintf("%d resource(s) changed in place", s.Change))
	}
	if total := s.Add + s.Change + s.Destroy + s.Replace; total > largeChange {
		raise(Medium, fmt.Sprintf("large change set (%d resources)", total))
	}
	var iam, net []string
	for _, r := range s.Resources {
		if !touches(r.Actions) {
			continue
		}
		switch {
		case identityType(r):
			iam = append(iam, r.Address)
		case networkType(r.Type):
			net = append(net, r.Address)
		}
	}
	if len(iam) > 0 {
		raise(High, "identity and access changes: "+short(iam))
	}
	if len(net) > 0 {
		if tier == TierProd {
			raise(High, "network exposure changes in production: "+short(net))
		} else {
			raise(Medium, "network exposure changes: "+short(net))
		}
	}
	if len(reasons) == 0 {
		reasons = []string{"only additions in a non-production environment"}
	}
	return Result{Level: level, Reasons: reasons, Steps: StepsFor(level)}
}

func StepsFor(level string) []string {
	switch level {
	case High:
		return []string{identity.StepManager, identity.StepFinOps, identity.StepSecurity}
	case Medium:
		return []string{identity.StepManager, identity.StepFinOps}
	}
	return []string{identity.StepManager}
}

func rank(l string) int { return map[string]int{Low: 0, Medium: 1, High: 2}[l] }

func touches(actions []string) bool {
	for _, a := range actions {
		if a == "create" || a == "update" || a == "delete" {
			return true
		}
	}
	return false
}

func identityType(r policy.ResourceChange) bool {
	t := r.Type
	if strings.HasPrefix(t, "aws_iam_") || strings.Contains(t, "_iam_") || strings.HasSuffix(t, "_iam") ||
		strings.HasPrefix(t, "google_service_account") || strings.HasPrefix(t, "azurerm_role_") ||
		strings.HasPrefix(t, "azuread_") || strings.HasPrefix(t, "aws_kms_grant") {
		return true
	}
	if t == "azapi_resource" {
		if typ, _ := r.After["type"].(string); strings.HasPrefix(typ, "Microsoft.Authorization/") {
			return true
		}
	}
	return false
}

var networkPrefixes = []string{
	"aws_security_group", "aws_vpc_security_group_", "aws_network_acl", "aws_eip", "aws_internet_gateway",
	"aws_lb", "aws_s3_bucket_policy", "aws_s3_bucket_public_access_block", "aws_route",
	"google_compute_firewall", "google_compute_address", "google_compute_global_address", "google_compute_route",
	"google_storage_bucket_iam", "azurerm_network_security", "azurerm_public_ip",
}

func networkType(t string) bool {
	for _, p := range networkPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

func short(xs []string) string {
	if len(xs) > 3 {
		return strings.Join(xs[:3], ", ") + fmt.Sprintf(" and %d more", len(xs)-3)
	}
	return strings.Join(xs, ", ")
}
