package risk

import (
	"reflect"
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
)

func rc(typ string, actions ...string) policy.ResourceChange {
	return policy.ResourceChange{Address: typ + ".x", Type: typ, Actions: actions}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name  string
		s     policy.Summary
		op    string
		tier  string
		level string
	}{
		{"additions in nonprod", policy.Summary{Add: 2, Resources: []policy.ResourceChange{rc("random_string", "create")}}, "apply", TierNonProd, Low},
		{"additions in prod", policy.Summary{Add: 1, Resources: []policy.ResourceChange{rc("aws_s3_bucket", "create")}}, "apply", TierProd, Medium},
		{"in-place change", policy.Summary{Change: 1, Resources: []policy.ResourceChange{rc("aws_s3_bucket", "update")}}, "apply", TierNonProd, Medium},
		{"network in nonprod", policy.Summary{Add: 1, Resources: []policy.ResourceChange{rc("aws_vpc_security_group_ingress_rule", "create")}}, "apply", TierNonProd, Medium},
		{"network in prod", policy.Summary{Add: 1, Resources: []policy.ResourceChange{rc("google_compute_firewall", "create")}}, "apply", TierProd, High},
		{"iam", policy.Summary{Add: 1, Resources: []policy.ResourceChange{rc("aws_iam_role", "create")}}, "apply", TierNonProd, High},
		{"gcp iam binding", policy.Summary{Add: 1, Resources: []policy.ResourceChange{rc("google_project_iam_member", "create")}}, "apply", TierNonProd, High},
		{"replacement", policy.Summary{Replace: 1, Resources: []policy.ResourceChange{rc("random_string", "delete", "create")}}, "apply", TierNonProd, High},
		{"destroy run", policy.Summary{Destroy: 1}, "destroy", TierNonProd, High},
		{"large", policy.Summary{Add: 30}, "apply", TierNonProd, Medium},
	}
	for _, c := range cases {
		r := Classify(c.s, c.op, c.tier)
		if r.Level != c.level {
			t.Errorf("%s: want %s, got %s (%v)", c.name, c.level, r.Level, r.Reasons)
		}
	}
	if got := Classify(policy.Summary{Destroy: 1}, "destroy", TierProd).Steps; !reflect.DeepEqual(got, []string{"manager", "finops", "security"}) {
		t.Errorf("high risk must need manager, finops and security, got %v", got)
	}
	if got := Classify(policy.Summary{Add: 1}, "apply", TierNonProd).Steps; !reflect.DeepEqual(got, []string{"manager"}) {
		t.Errorf("low risk needs only the manager, got %v", got)
	}
}

func TestSettings(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.ProdLevel = High
	cfg.CostMedium, cfg.CostHigh = 50, 500
	if l := ClassifyWith(policy.Summary{Add: 1}, "apply", TierProd, 0, cfg).Level; l != High {
		t.Errorf("prod_level high: got %s", l)
	}
	if l := ClassifyWith(policy.Summary{Add: 1}, "apply", TierNonProd, 60, cfg).Level; l != Medium {
		t.Errorf("cost above medium threshold: got %s", l)
	}
	if l := ClassifyWith(policy.Summary{Add: 1}, "apply", TierNonProd, 600, cfg).Level; l != High {
		t.Errorf("cost above high threshold: got %s", l)
	}
	if l := ClassifyWith(policy.Summary{Add: 1, Imports: 1}, "apply", TierNonProd, 0, Default()).Level; l != Medium {
		t.Errorf("imports raise risk: got %s", l)
	}
	bad := []func(*Settings){
		func(s *Settings) { s.Approvals[Low] = nil },
		func(s *Settings) { s.Approvals[High] = []string{"manager", "finops"} },
		func(s *Settings) { s.Approvals[Medium] = []string{"manager", "finops", "security", "manager"} },
		func(s *Settings) {
			s.Approvals[Medium] = []string{"manager"}
			s.Approvals[Low] = []string{"manager", "finops"}
		},
		func(s *Settings) { s.ProdLevel = "low" },
		func(s *Settings) { s.CostMedium, s.CostHigh = 900, 100 },
		func(s *Settings) { s.Approvals["critical"] = []string{"security"} },
	}
	for i, mutate := range bad {
		c := Default()
		mutate(&c)
		if c.Validate() == nil {
			t.Errorf("bad settings %d accepted", i)
		}
	}
}
