package api

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/cost"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/opapolicy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

var (
	psNameRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,47}$`)
	psScopeRe = regexp.MustCompile(`^(tenant|entity:[a-z][a-z0-9-]{1,31}|bu:[a-z][a-z0-9-]{1,31})$`)
)

type policyBody struct {
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	Level   string `json:"level"`
	Module  string `json:"module"`
	Enabled *bool  `json:"enabled"`
}

// Policy sets are written by tenant admins or security; everyone may read them.
func canWritePolicy(w http.ResponseWriter, r *http.Request) bool {
	if !user(r).HasTenantRole(identity.TenantAdmin, identity.Security) {
		writeErr(w, http.StatusForbidden, "policy sets need tenant_admin or security")
		return false
	}
	return true
}

func (b *policyBody) check(w http.ResponseWriter, create bool) bool {
	var probs []string
	if create && !psNameRe.MatchString(b.Name) {
		probs = append(probs, "name must be lowercase letters, digits and dashes")
	}
	if !psScopeRe.MatchString(b.Scope) {
		probs = append(probs, `scope must be "tenant", "entity:<slug>" or "bu:<slug>"`)
	}
	if b.Level != "hard" && b.Level != "advisory" {
		probs = append(probs, `level must be "hard" or "advisory"`)
	}
	if err := opapolicy.Compile(b.Module); err != nil {
		probs = append(probs, "rego: "+err.Error())
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid policy set", probs...)
		return false
	}
	return true
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListPolicySets(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, ps)
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	if !canWritePolicy(w, r) {
		return
	}
	var b policyBody
	if !decode(w, r, &b) || !b.check(w, true) {
		return
	}
	enabled := b.Enabled == nil || *b.Enabled
	p, err := s.store.CreatePolicySet(r.Context(), &store.PolicySet{Name: b.Name, Scope: b.Scope, Level: b.Level, Module: b.Module, Enabled: enabled, CreatedBy: user(r).Subject})
	if err != nil {
		s.writeStoreErr(w, err, "a policy set with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "policy.create", "policy/"+p.Name, "", p)
	writeJSON(w, 201, p)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	if !canWritePolicy(w, r) {
		return
	}
	cur, err := s.store.GetPolicySet(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	var b policyBody
	if !decode(w, r, &b) || !b.check(w, false) {
		return
	}
	enabled := b.Enabled == nil || *b.Enabled
	p, err := s.store.UpdatePolicySet(r.Context(), &store.PolicySet{ID: cur.ID, Scope: b.Scope, Level: b.Level, Module: b.Module, Enabled: enabled, UpdatedBy: user(r).Subject})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "policy.update", "policy/"+p.Name, "", map[string]any{"before": cur, "after": p})
	writeJSON(w, 200, p)
}

func (s *Server) deletePolicy(w http.ResponseWriter, r *http.Request) {
	if !canWritePolicy(w, r) {
		return
	}
	cur, err := s.store.GetPolicySet(r.Context(), r.PathValue("id"))
	if err == nil {
		err = s.store.DeletePolicySet(r.Context(), cur.ID)
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "policy.delete", "policy/"+cur.Name, "", cur)
	w.WriteHeader(http.StatusNoContent)
}

// testPolicy is a dry run: it compiles a module and evaluates it against the
// given input, or against a past run's plan.
func (s *Server) testPolicy(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Module string         `json:"module"`
		RunID  string         `json:"run_id"`
		Input  map[string]any `json:"input"`
	}
	if !decode(w, r, &b) {
		return
	}
	if err := opapolicy.Compile(b.Module); err != nil {
		writeErr(w, 422, "rego: "+err.Error())
		return
	}
	input := b.Input
	if b.RunID != "" {
		run := s.visibleRunByID(w, r, b.RunID)
		if run == nil {
			return
		}
		var sum policy.Summary
		json.Unmarshal(run.PlanSummary, &sum)
		env, _ := s.store.GetEnvironment(r.Context(), run.Environment)
		input = s.policyInput(run, env, sum)
	}
	writeJSON(w, 200, opapolicy.Evaluate(r.Context(), []opapolicy.Set{{Name: "test", Level: "hard", Module: b.Module}}, input))
}

func (s *Server) visibleRunByID(w http.ResponseWriter, r *http.Request, id string) *store.Run {
	run, err := s.store.GetRun(r.Context(), id)
	if err == nil && !user(r).CanView(run.BU) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil
	}
	return run
}

// policyInput is the document policies see.
func (s *Server) policyInput(run *store.Run, env *store.Environment, sum policy.Summary) map[string]any {
	var in map[string]any
	b, _ := json.Marshal(map[string]any{
		"run": map[string]any{
			"id": run.ID, "operation": run.Operation, "stack": run.StackName, "bu": run.BU, "entity": run.Entity,
			"environment": run.Environment, "tier": envTier(env), "created_by": run.CreatedBy,
		},
		"summary": sum,
		"cost":    cost.Of(sum),
	})
	json.Unmarshal(b, &in)
	return in
}

func envTier(e *store.Environment) string {
	if e == nil {
		return ""
	}
	return e.Tier
}

// tenantPolicies returns the enabled sets that apply to a run's BU and entity.
func (s *Server) tenantPolicies(ctx context.Context, run *store.Run) []opapolicy.Set {
	all, err := s.store.ListPolicySets(ctx)
	if err != nil {
		s.log.Error("loading policy sets", "err", err)
		return []opapolicy.Set{{Name: "unavailable", Level: "hard", Module: "package pravaha.policy\ndeny contains \"policy sets could not be loaded\" if true"}}
	}
	var out []opapolicy.Set
	for _, p := range all {
		if p.Enabled && (p.Scope == "tenant" || p.Scope == "entity:"+run.Entity || p.Scope == "bu:"+run.BU) {
			out = append(out, opapolicy.Set{Name: p.Name, Level: p.Level, Module: p.Module})
		}
	}
	return out
}
