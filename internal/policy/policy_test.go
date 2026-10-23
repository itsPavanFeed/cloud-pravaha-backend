package policy

import "testing"

func TestPolicy(t *testing.T) {
	lim := Limits{MaxDestroys: 1}
	ok := Evaluate(Summary{Add: 1, Resources: []ResourceChange{{Address: "random_string.x", Type: "random_string", Actions: []string{"create"}}}}, lim)
	if !ok.Passed {
		t.Fatal(ok)
	}
	cases := map[string]Summary{
		"too many destroys": {Destroy: 2},
		"static key":        {Add: 1, Resources: []ResourceChange{{Type: "aws_iam_access_key", Actions: []string{"create"}}}},
		"open ingress":      {Add: 1, Resources: []ResourceChange{{Type: "aws_vpc_security_group_ingress_rule", Actions: []string{"create"}, After: map[string]any{"cidr_ipv4": "0.0.0.0/0"}}}},
		"public bucket":     {Add: 1, Resources: []ResourceChange{{Type: "aws_s3_bucket_public_access_block", Actions: []string{"create"}, After: map[string]any{"block_public_acls": false}}}},
		"gcs public":        {Add: 1, Resources: []ResourceChange{{Type: "google_storage_bucket", Actions: []string{"create"}, After: map[string]any{"public_access_prevention": "inherited"}}}},
	}
	for name, s := range cases {
		if Evaluate(s, lim).Passed {
			t.Errorf("%s: expected a hard violation", name)
		}
	}
	if Evaluate(Summary{Destroy: 5}, Limits{Destroying: true, AllowDestroy: true}).Passed != true {
		t.Error("allowed destroy runs are not subject to the per-run limit")
	}
	if Evaluate(Summary{Destroy: 5}, Limits{Destroying: true}).Passed {
		t.Error("destroy must be blocked when the environment disallows it")
	}
}
