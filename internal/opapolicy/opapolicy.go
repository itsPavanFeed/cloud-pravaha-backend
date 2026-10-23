// Package opapolicy evaluates tenant-defined Rego policy sets against plans.
//
// A policy set is a Rego module in package pravaha.policy. Each element of its
// deny set is a violation: a string, or an object {"msg": ..., "address": ...}.
// Policy sets fail closed: a set that does not compile, errors or times out
// produces a hard violation rather than passing the plan.
package opapolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
)

const (
	Package = "pravaha.policy"
	query   = "data.pravaha.policy.deny"
	timeout = 2 * time.Second
	maxSize = 64 << 10
)

// Compile checks a module before it is stored.
func Compile(module string) error {
	if len(module) > maxSize {
		return fmt.Errorf("policy is larger than %d KiB", maxSize>>10)
	}
	m, err := ast.ParseModuleWithOpts("policy.rego", module, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return err
	}
	if m.Package.Path.String() != "data."+Package {
		return fmt.Errorf("policy must declare `package %s`", Package)
	}
	c := ast.NewCompiler()
	if c.Compile(map[string]*ast.Module{"policy.rego": m}); c.Failed() {
		return c.Errors
	}
	return nil
}

// Set is one stored policy set as evaluated.
type Set struct {
	Name   string
	Level  string // hard | advisory
	Module string
}

// Evaluate runs every set against input and returns their violations.
func Evaluate(ctx context.Context, sets []Set, input map[string]any) []policy.Violation {
	var out []policy.Violation
	for _, s := range sets {
		out = append(out, evalOne(ctx, s, input)...)
	}
	return out
}

func evalOne(ctx context.Context, s Set, input map[string]any) []policy.Violation {
	rule := "opa:" + s.Name
	fail := func(err error) []policy.Violation {
		return []policy.Violation{{Rule: rule, Level: "hard", Message: "policy set could not be evaluated (failing closed): " + err.Error()}}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r := rego.New(
		rego.Query(query),
		rego.Module("policy.rego", s.Module),
		rego.SetRegoVersion(ast.RegoV1),
		rego.Input(input),
		rego.StrictBuiltinErrors(true),
	)
	rs, err := r.Eval(ctx)
	if err != nil {
		return fail(err)
	}
	var out []policy.Violation
	for _, res := range rs {
		for _, expr := range res.Expressions {
			items, ok := expr.Value.([]any)
			if !ok {
				return fail(fmt.Errorf("deny must be a set, got %T", expr.Value))
			}
			for _, it := range items {
				v := policy.Violation{Rule: rule, Level: s.Level}
				switch t := it.(type) {
				case string:
					v.Message = t
				case map[string]any:
					v.Message, _ = t["msg"].(string)
					v.Address, _ = t["address"].(string)
				}
				if strings.TrimSpace(v.Message) == "" {
					v.Message = fmt.Sprint(it)
				}
				if len(v.Message) > 500 {
					v.Message = v.Message[:500]
				}
				out = append(out, v)
			}
		}
	}
	return out
}
