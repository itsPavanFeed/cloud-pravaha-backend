// Package risk classifies a plan and decides which approvals it needs.
//
//	low     only additions in a non-production environment       manager
//	medium  in-place changes, production, network resources,      manager + finops
//	        or a large change set
//	high    deletions or replacements, destroy runs, identity        manager + finops + security
//	        and access changes, or network exposure in production
package risk

import (
	"errors"
	"fmt"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
)

const (
	Low    = "low"
	Medium = "medium"
	High   = "high"

	defaultLargeChange = 25
)

// Settings are a tenant's risk policy. Zero values are never used: Default()
// fills them and Validate() rejects anything incoherent.
type Settings struct {
	LargeChange int                 `json:"large_change"`    // more changes than this raise risk to medium
	ProdLevel   string              `json:"prod_level"`      // minimum risk for production environments: medium or high
	CostMedium  float64             `json:"cost_medium_usd"` // monthly increase that raises risk to medium (0 = off)
	CostHigh    float64             `json:"cost_high_usd"`   // monthly increase that raises risk to high (0 = off)
	Approvals   map[string][]string `json:"approvals"`       // risk level -> required approval steps
}

func Default() Settings {
	return Settings{LargeChange: defaultLargeChange, ProdLevel: Medium, CostMedium: 100, CostHigh: 1000, Approvals: map[string][]string{
		Low:    {identity.StepManager},
		Medium: {identity.StepManager, identity.StepFinOps},
		High:   {identity.StepManager, identity.StepFinOps, identity.StepSecurity},
	}}
}

// Validate keeps a tenant from weakening the chain below a sane floor: every
// level needs at least one approval, high risk always needs security, and a
// higher level never needs fewer approvals than a lower one.
func (s Settings) Validate() error {
	var errs []error
	if s.LargeChange < 1 || s.LargeChange > 10000 {
		errs = append(errs, errors.New("large_change must be between 1 and 10000"))
	}
	if s.ProdLevel != Medium && s.ProdLevel != High {
		errs = append(errs, errors.New(`prod_level must be "medium" or "high"`))
	}
	if s.CostMedium < 0 || s.CostHigh < 0 || (s.CostHigh > 0 && s.CostMedium > s.CostHigh) {
		errs = append(errs, errors.New("cost thresholds must be positive, with cost_medium_usd at or below cost_high_usd (0 disables one)"))
	}
	prev := 0
	for _, l := range []string{Low, Medium, High} {
		steps := s.Approvals[l]
		if len(steps) == 0 {
			errs = append(errs, fmt.Errorf("risk level %s needs at least one approval", l))
		}
		seen := map[string]bool{}
		for _, st := range steps {
			if seen[st] || (st != identity.StepManager && st != identity.StepFinOps && st != identity.StepSecurity) {
				errs = append(errs, fmt.Errorf("risk level %s: invalid or repeated step %q", l, st))
			}
			seen[st] = true
		}
		if len(steps) < prev {
			errs = append(errs, fmt.Errorf("risk level %s cannot need fewer approvals than a lower level", l))
		}
		prev = len(steps)
		if l == High && !seen[identity.StepSecurity] {
			errs = append(errs, errors.New("high risk must always include the security approval"))
		}
	}
	for l := range s.Approvals {
		if l != Low && l != Medium && l != High {
			errs = append(errs, fmt.Errorf("unknown risk level %q", l))
		}
	}
	return errors.Join(errs...)
}

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

// Classify uses the default settings and no cost information.
func Classify(s policy.Summary, operation, tier string) Result {
	return ClassifyWith(s, operation, tier, 0, Default())
}

// ClassifyWith applies a tenant's settings and the plan's monthly cost increase.
func ClassifyWith(s policy.Summary, operation, tier string, monthlyDelta float64, cfg Settings) Result {
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
		raise(cfg.ProdLevel, "production environment")
	}
	if cfg.CostHigh > 0 && monthlyDelta >= cfg.CostHigh {
		raise(High, fmt.Sprintf("estimated cost increase $%.2f/month", monthlyDelta))
	} else if cfg.CostMedium > 0 && monthlyDelta >= cfg.CostMedium {
		raise(Medium, fmt.Sprintf("estimated cost increase $%.2f/month", monthlyDelta))
	}
	if imports := s.Imports; imports > 0 {
		raise(Medium, fmt.Sprintf("%d existing resource(s) imported", imports))
	}
	if s.Change > 0 {
		raise(Medium, fmt.Sprintf("%d resource(s) changed in place", s.Change))
	}
	if total := s.Add + s.Change + s.Destroy + s.Replace; total > cfg.LargeChange {
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
	return Result{Level: level, Reasons: reasons, Steps: append([]string(nil), cfg.Approvals[level]...)}
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
