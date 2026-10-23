package opapolicy

import (
	"context"
	"testing"
)

const requireTags = `package pravaha.policy

deny contains {"msg": sprintf("%s has no team tag", [r.address]), "address": r.address} if {
	some r in input.summary.resources
	r.type == "aws_s3_bucket"
	"create" in r.actions
	not r.after.tags.team
}

deny contains "production changes need a ticket in the stack name" if {
	input.run.tier == "prod"
	not startswith(input.run.stack, "chg-")
}
`

func TestPolicySets(t *testing.T) {
	if err := Compile(requireTags); err != nil {
		t.Fatal(err)
	}
	input := map[string]any{
		"run": map[string]any{"tier": "prod", "stack": "payments"},
		"summary": map[string]any{"resources": []any{
			map[string]any{"address": "module.b.aws_s3_bucket.this[0]", "type": "aws_s3_bucket", "actions": []any{"create"}, "after": map[string]any{"tags": map[string]any{}}},
		}},
	}
	v := Evaluate(context.Background(), []Set{{Name: "tags", Level: "hard", Module: requireTags}}, input)
	if len(v) != 2 || v[0].Level != "hard" || v[0].Rule != "opa:tags" {
		t.Fatalf("violations: %+v", v)
	}
	for _, bad := range []string{
		"package other\ndeny contains 1 if true",
		"package pravaha.policy\ndeny contains x if {",
	} {
		if Compile(bad) == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	// A runtime error fails closed.
	broken := "package pravaha.policy\ndeny contains x if { x := 1 / input.zero }"
	if v := Evaluate(context.Background(), []Set{{Name: "b", Level: "advisory", Module: broken}}, map[string]any{"zero": 0}); len(v) != 1 || v[0].Level != "hard" {
		t.Fatalf("broken policy must fail closed: %+v", v)
	}
}
