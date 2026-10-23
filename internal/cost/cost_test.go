package cost

import (
	"testing"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
)

func TestEstimate(t *testing.T) {
	e := Of(policy.Summary{Resources: []policy.ResourceChange{
		{Address: "a", Type: "aws_nat_gateway", Actions: []string{"create"}},
		{Address: "b", Type: "aws_instance", Actions: []string{"create"}, After: map[string]any{"instance_type": "m5.large"}},
		{Address: "c", Type: "aws_eip", Actions: []string{"delete"}},
		{Address: "d", Type: "random_string", Actions: []string{"create"}},
		{Address: "e", Type: "aws_instance", Actions: []string{"delete", "create"}},
	}})
	want := round(0.045*hours + 0.096*hours - 0.005*hours)
	if e.MonthlyDelta != want || len(e.Items) != 3 || e.Unpriced != 1 || e.Items[0].Address != "b" {
		t.Fatalf("got %+v, want delta %v", e, want)
	}
}
