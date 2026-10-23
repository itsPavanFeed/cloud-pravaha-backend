// Package cost gives an approximate monthly cost change for a plan, so FinOps
// approvers see a number and risk can rise with spend.
//
// Prices are list on-demand USD per month (730 hours) for common fixed-cost
// resources in us-east-1 / us-central1 / eastus. Usage-based resources (storage,
// requests, data transfer) are not priced. The estimate is a review aid, not a bill.
package cost

import (
	"math"
	"sort"
	"strings"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
)

const hours = 730.0

// Fixed monthly prices by resource type.
var fixed = map[string]float64{
	"aws_nat_gateway":            0.045 * hours,
	"aws_eip":                    0.005 * hours,
	"aws_lb":                     0.0225 * hours,
	"aws_alb":                    0.0225 * hours,
	"aws_eks_cluster":            0.10 * hours,
	"aws_kms_key":                1,
	"aws_vpc_endpoint":           0.01 * hours,
	"aws_secretsmanager_secret":  0.40,
	"google_container_cluster":   0.10 * hours,
	"google_compute_router_nat":  0.044 * hours,
	"google_compute_address":     0.005 * hours,
	"google_kms_crypto_key":      0.06,
	"azurerm_public_ip":          0.005 * hours,
	"azurerm_kubernetes_cluster": 0.10 * hours,
}

// Hourly prices by instance size for compute and databases.
var sized = map[string]map[string]float64{
	"aws_instance": {
		"t3.nano": 0.0052, "t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664,
		"m5.large": 0.096, "m5.xlarge": 0.192, "m5.2xlarge": 0.384, "c5.large": 0.085, "c5.xlarge": 0.17, "r5.large": 0.126,
	},
	"aws_db_instance": {
		"db.t3.micro": 0.017, "db.t3.small": 0.034, "db.t3.medium": 0.068, "db.t3.large": 0.136,
		"db.m5.large": 0.171, "db.m5.xlarge": 0.342, "db.r5.large": 0.24,
	},
	"google_compute_instance": {
		"e2-micro": 0.0084, "e2-small": 0.0168, "e2-medium": 0.0335, "e2-standard-2": 0.067, "e2-standard-4": 0.134,
		"n2-standard-2": 0.0971, "n2-standard-4": 0.1942,
	},
	"google_sql_database_instance": {"db-f1-micro": 0.0105, "db-g1-small": 0.035, "db-custom-1-3840": 0.0413, "db-custom-2-7680": 0.0826},
}

// Attribute holding the size for sized resource types.
var sizeAttr = map[string][]string{
	"aws_instance":                 {"instance_type"},
	"aws_db_instance":              {"instance_class"},
	"google_compute_instance":      {"machine_type"},
	"google_sql_database_instance": {"tier"},
}

type Item struct {
	Address string  `json:"address"`
	Type    string  `json:"type"`
	Monthly float64 `json:"monthly_usd"` // signed: negative for removals
	Basis   string  `json:"basis"`
}

type Estimate struct {
	MonthlyDelta float64 `json:"monthly_delta_usd"`
	Items        []Item  `json:"items"`
	Unpriced     int     `json:"unpriced_resources"`
	Note         string  `json:"note"`
}

// Of prices additions (+) and removals (-); replacements and in-place
// changes are treated as cost-neutral unless the size attribute is visible.
func Of(s policy.Summary) Estimate {
	e := Estimate{Items: []Item{}, Note: "approximate list prices for fixed-cost resources; usage-based charges are not included"}
	for _, r := range s.Resources {
		sign := 0.0
		switch {
		case len(r.Actions) == 1 && r.Actions[0] == "create":
			sign = 1
		case len(r.Actions) == 1 && r.Actions[0] == "delete":
			sign = -1
		default:
			continue
		}
		price, basis, ok := monthly(r)
		if !ok {
			e.Unpriced++
			continue
		}
		e.Items = append(e.Items, Item{Address: r.Address, Type: r.Type, Monthly: round(sign * price), Basis: basis})
		e.MonthlyDelta += sign * price
	}
	e.MonthlyDelta = round(e.MonthlyDelta)
	sort.Slice(e.Items, func(i, j int) bool { return math.Abs(e.Items[i].Monthly) > math.Abs(e.Items[j].Monthly) })
	return e
}

func monthly(r policy.ResourceChange) (float64, string, bool) {
	if p, ok := fixed[r.Type]; ok {
		return p, "fixed monthly price", true
	}
	if table, ok := sized[r.Type]; ok {
		for _, attr := range sizeAttr[r.Type] {
			if size, _ := r.After[attr].(string); size != "" {
				size = size[strings.LastIndex(size, "/")+1:]
				if h, ok := table[size]; ok {
					return h * hours, size + " on-demand", true
				}
			}
		}
	}
	return 0, "", false
}

func round(f float64) float64 { return math.Round(f*100) / 100 }
