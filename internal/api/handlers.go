package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/risk"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

var (
	envNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	poolRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	runnerRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}$`)
	reasonMax = 500
)

// forbidden answers 404 rather than 403 for resources in entities the caller
// cannot see, so business units cannot discover each other's stacks.
func forbidden(w http.ResponseWriter, visible bool, msg string) {
	if !visible {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeErr(w, http.StatusForbidden, msg)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, user(r))
}

func (s *Server) getCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"registry": "registry.opentofu.org", "modules": s.catalog.Modules, "providers": s.catalog.Providers, "tofu_version": s.cfg.TofuVersion})
}

// ---- environments ----

type envBody struct {
	Name         string          `json:"name"`
	Entity       string          `json:"entity"`
	Tier         string          `json:"tier"`
	Cloud        json.RawMessage `json:"cloud"`
	RunnerPool   string          `json:"runner_pool"`
	MaxDestroys  *int            `json:"max_destroys"`
	AllowDestroy bool            `json:"allow_destroy"`
}

func (b *envBody) validate(create bool) (*spec.Cloud, []string) {
	var probs []string
	if create && !envNameRe.MatchString(b.Name) {
		probs = append(probs, "name must be lowercase letters, digits and dashes (2-32)")
	}
	if create && !identity.SlugRe.MatchString(b.Entity) {
		probs = append(probs, "entity must be the business unit's slug")
	}
	if b.Tier != risk.TierProd && b.Tier != risk.TierNonProd {
		probs = append(probs, `tier must be "prod" or "nonprod"`)
	}
	if !poolRe.MatchString(b.RunnerPool) {
		probs = append(probs, "runner_pool must be lowercase letters, digits and dashes (2-32)")
	}
	if b.MaxDestroys == nil || *b.MaxDestroys < 0 || *b.MaxDestroys > 1000 {
		probs = append(probs, "max_destroys must be between 0 and 1000")
	}
	c, err := spec.DecodeCloud(b.Cloud)
	if err != nil {
		probs = append(probs, errLines(err)...)
	}
	return c, probs
}

func (s *Server) listEnvironments(w http.ResponseWriter, r *http.Request) {
	envs, err := s.store.ListEnvironments(r.Context(), visible(r))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, envs)
}

func (s *Server) getEnvironment(w http.ResponseWriter, r *http.Request) {
	e, err := s.store.GetEnvironment(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanView(e.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"environment": e}
	if c, err := spec.DecodeCloud(e.Cloud); err == nil && c.NeedsOIDCToken() {
		resp["oidc"] = map[string]string{
			"issuer":          s.issuer.URL,
			"audience":        c.Audience(),
			"subject_pattern": "pravaha:env:" + e.Name + ":stack:*",
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) createEnvironment(w http.ResponseWriter, r *http.Request) {
	var b envBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	if !p.CanManageEnvironments(b.Entity) {
		forbidden(w, p.CanView(b.Entity) || b.Entity == "", "managing environments needs tenant_admin, or admin of the entity")
		return
	}
	c, probs := b.validate(true)
	if len(probs) > 0 {
		writeErr(w, 422, "invalid environment", probs...)
		return
	}
	cloud, _ := json.Marshal(c)
	e, err := s.store.CreateEnvironment(r.Context(), &store.Environment{Name: b.Name, Entity: b.Entity, Tier: b.Tier, Cloud: cloud, RunnerPool: b.RunnerPool,
		MaxDestroys: *b.MaxDestroys, AllowDestroy: b.AllowDestroy, CreatedBy: p.Subject})
	if err != nil {
		s.writeStoreErr(w, err, "an environment with that name exists")
		return
	}
	s.audit(r.Context(), p.Actor(), "environment.create", "environment/"+e.Name, e.Entity, e)
	writeJSON(w, 201, e)
}

func (s *Server) updateEnvironment(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	cur, err := s.store.GetEnvironment(r.Context(), r.PathValue("id"))
	if err == nil && !p.CanView(cur.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if !p.CanManageEnvironments(cur.Entity) {
		writeErr(w, http.StatusForbidden, "managing environments needs tenant_admin, or admin of the entity")
		return
	}
	var b envBody
	if !decode(w, r, &b) {
		return
	}
	c, probs := b.validate(false)
	if len(probs) > 0 {
		writeErr(w, 422, "invalid environment", probs...)
		return
	}
	cloud, _ := json.Marshal(c)
	e, err := s.store.UpdateEnvironment(r.Context(), &store.Environment{ID: cur.ID, Tier: b.Tier, Cloud: cloud, RunnerPool: b.RunnerPool, MaxDestroys: *b.MaxDestroys, AllowDestroy: b.AllowDestroy})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "environment.update", "environment/"+e.Name, e.Entity, map[string]any{"before": cur, "after": e})
	writeJSON(w, 200, e)
}

// ---- stacks ----

type stackBody struct {
	Name        string          `json:"name"`
	Environment string          `json:"environment"`
	Spec        json.RawMessage `json:"spec"`
}

// build validates a spec for an environment and generates its configuration.
func (s *Server) build(ctx context.Context, stackName string, env *store.Environment, raw []byte) (*spec.Generated, *spec.Cloud, []string) {
	c, err := spec.DecodeCloud(env.Cloud)
	if err != nil {
		return nil, nil, []string{"environment cloud integration is invalid: " + err.Error()}
	}
	st, err := spec.Decode(raw)
	if err != nil {
		return nil, nil, []string{err.Error()}
	}
	gen, err := st.Generate(s.catalog, spec.GenerateInput{
		StackName: stackName, Environment: env.Name, Cloud: c, TofuVersion: s.cfg.TofuVersion,
	})
	if err != nil {
		return nil, nil, errLines(err)
	}
	return gen, c, nil
}

// normalizeSpec re-encodes a spec so stored specs are canonical (versions filled in).
func normalizeSpec(raw []byte) []byte {
	st, err := spec.Decode(raw)
	if err != nil {
		return raw
	}
	b, _ := json.Marshal(st)
	return b
}

// visibleEnv loads an environment the caller can see, or answers 422.
func (s *Server) visibleEnv(w http.ResponseWriter, r *http.Request, name string) *store.Environment {
	env, err := s.store.GetEnvironment(r.Context(), name)
	if err != nil || !user(r).CanView(env.Entity) {
		writeErr(w, 422, "unknown environment")
		return nil
	}
	return env
}

func (s *Server) previewStack(w http.ResponseWriter, r *http.Request) {
	var b stackBody
	if !decode(w, r, &b) {
		return
	}
	env := s.visibleEnv(w, r, b.Environment)
	if env == nil {
		return
	}
	name := b.Name
	if !spec.StackNameRe.MatchString(name) {
		name = "preview"
	}
	gen, _, probs := s.build(r.Context(), name, env, b.Spec)
	if probs != nil {
		writeJSON(w, 200, map[string]any{"valid": false, "problems": probs})
		return
	}
	files := map[string]string{}
	for k, v := range gen.Files {
		files[k] = string(v)
	}
	writeJSON(w, 200, map[string]any{"valid": true, "files": files, "providers": gen.Providers, "modules": gen.Modules, "hash": gen.Hash})
}

// createStack: the stack belongs to its environment's entity.
func (s *Server) createStack(w http.ResponseWriter, r *http.Request) {
	var b stackBody
	if !decode(w, r, &b) {
		return
	}
	p := user(r)
	if !spec.StackNameRe.MatchString(b.Name) {
		writeErr(w, 422, "name must start with a letter and use lowercase letters, digits and dashes (2-63)")
		return
	}
	env := s.visibleEnv(w, r, b.Environment)
	if env == nil {
		return
	}
	if !p.CanChange(env.Entity) {
		writeErr(w, http.StatusForbidden, "creating stacks needs the developer or admin role in "+env.Entity)
		return
	}
	if _, _, probs := s.build(r.Context(), b.Name, env, b.Spec); probs != nil {
		writeErr(w, 422, "stack spec rejected", probs...)
		return
	}
	st, err := s.store.CreateStack(r.Context(), b.Name, env.Entity, env.ID, normalizeSpec(b.Spec), p.Subject)
	if err != nil {
		s.writeStoreErr(w, err, "a stack with that name exists")
		return
	}
	s.audit(r.Context(), p.Actor(), "stack.create", "stack/"+st.Name, st.Entity, map[string]any{"environment": env.Name, "spec": st.Spec})
	writeJSON(w, 201, st)
}

// visibleStack loads a stack the caller can see, or answers 404.
func (s *Server) visibleStack(w http.ResponseWriter, r *http.Request) *store.Stack {
	st, err := s.store.GetStack(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanView(st.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil
	}
	return st
}

func (s *Server) updateStack(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.Entity) {
		writeErr(w, http.StatusForbidden, "editing stacks needs the developer or admin role in "+st.Entity)
		return
	}
	var b struct {
		Spec json.RawMessage `json:"spec"`
	}
	if !decode(w, r, &b) {
		return
	}
	env, err := s.store.GetEnvironment(r.Context(), st.EnvironmentID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if _, _, probs := s.build(r.Context(), st.Name, env, b.Spec); probs != nil {
		writeErr(w, 422, "stack spec rejected", probs...)
		return
	}
	if err := s.store.UpdateStack(r.Context(), st.ID, normalizeSpec(b.Spec)); err != nil {
		s.writeStoreErr(w, err, "the stack has an active run; finish or discard it first")
		return
	}
	s.audit(r.Context(), p.Actor(), "stack.update", "stack/"+st.Name, st.Entity, map[string]any{"before": st.Spec, "after": json.RawMessage(normalizeSpec(b.Spec))})
	st, _ = s.store.GetStack(r.Context(), st.ID)
	writeJSON(w, 200, st)
}

func visible(r *http.Request) []string { return user(r).VisibleEntities() }

func (s *Server) listStacks(w http.ResponseWriter, r *http.Request) {
	sts, err := s.store.ListStacks(r.Context(), visible(r))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, sts)
}

func (s *Server) getStack(w http.ResponseWriter, r *http.Request) {
	if st := s.visibleStack(w, r); st != nil {
		writeJSON(w, 200, st)
	}
}

func (s *Server) listStateVersions(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	vs, err := s.store.StateVersions(r.Context(), st.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, vs)
}

// ---- runs ----

func (s *Server) createRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	if !p.CanChange(st.Entity) {
		writeErr(w, http.StatusForbidden, "starting runs needs the developer or admin role in "+st.Entity)
		return
	}
	var b struct {
		Operation string `json:"operation"`
	}
	if !decode(w, r, &b) {
		return
	}
	if b.Operation == "" {
		b.Operation = "apply"
	}
	if b.Operation != "apply" && b.Operation != "destroy" {
		writeErr(w, 422, `operation must be "apply" or "destroy"`)
		return
	}
	env, err := s.store.GetEnvironment(r.Context(), st.EnvironmentID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if b.Operation == "destroy" && !env.AllowDestroy {
		writeErr(w, http.StatusForbidden, "destroy runs are disabled for environment "+env.Name)
		return
	}
	gen, _, probs := s.build(r.Context(), st.Name, env, st.Spec)
	if probs != nil {
		writeErr(w, 422, "stack no longer validates against the catalog", probs...)
		return
	}
	run, err := s.store.CreateRun(r.Context(), st.ID, b.Operation, p.Subject, gen.Hash)
	if err != nil {
		s.writeStoreErr(w, err, "the stack already has an active run")
		return
	}
	s.audit(r.Context(), p.Actor(), "run.create", "run/"+run.ID, st.Entity, map[string]string{"stack": st.Name, "operation": b.Operation, "config_hash": gen.Hash})
	s.notify()
	writeJSON(w, 201, run)
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListRuns(r.Context(), "", visible(r), limit(r, 50, 200))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, runs)
}

func (s *Server) listStackRuns(w http.ResponseWriter, r *http.Request) {
	st := s.visibleStack(w, r)
	if st == nil {
		return
	}
	runs, err := s.store.ListRuns(r.Context(), st.ID, nil, limit(r, 50, 200))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, runs)
}

func (s *Server) visibleRun(w http.ResponseWriter, r *http.Request) *store.Run {
	run, err := s.store.GetRun(r.Context(), r.PathValue("id"))
	if err == nil && !user(r).CanView(run.Entity) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil
	}
	return run
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) {
	if run := s.visibleRun(w, r); run != nil {
		writeJSON(w, 200, run)
	}
}

func (s *Server) getRunLogs(w http.ResponseWriter, r *http.Request) {
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	logs, err := s.store.Logs(r.Context(), run.ID, after)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, logs)
}

// approveRun signs one step of the run's approval chain (manager, finops,
// security, as its risk requires). Every signature re-checks that the plan is
// still current; the last one queues the apply.
func (s *Server) approveRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	var b struct {
		Step   string `json:"step"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Reason) > reasonMax {
		writeErr(w, 422, "reason is too long")
		return
	}
	if !p.CanApprove(b.Step, run.Entity) {
		writeErr(w, http.StatusForbidden, "you cannot sign the "+b.Step+" approval for "+run.Entity)
		return
	}
	if run.Status != "planned" {
		writeErr(w, http.StatusConflict, "only planned runs can be approved (status is "+run.Status+")")
		return
	}
	var pr policy.Result
	if json.Unmarshal(run.PolicyResult, &pr) != nil || !pr.Passed {
		writeErr(w, http.StatusConflict, "the plan did not pass policy")
		return
	}
	st, err := s.store.GetStack(r.Context(), run.StackID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	env, err := s.store.GetEnvironment(r.Context(), st.EnvironmentID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	gen, _, probs := s.build(r.Context(), st.Name, env, st.Spec)
	_, serial, serr := s.store.CurrentState(r.Context(), st.ID)
	stale := ""
	switch {
	case probs != nil || gen.Hash != run.ConfigHash:
		stale = "the stack or environment changed after this plan was made"
	case serr != nil || run.StateSerial == nil || serial != *run.StateSerial:
		stale = "the stack's state changed after this plan was made"
	}
	if stale != "" {
		s.store.Discard(r.Context(), run.ID, "stale plan: "+stale)
		s.audit(r.Context(), p.Actor(), "run.discard", "run/"+run.ID, run.Entity, map[string]string{"reason": "stale plan: " + stale})
		writeErr(w, http.StatusConflict, "plan is stale and was discarded: "+stale+"; start a new run")
		return
	}
	complete, err := s.store.Approve(r.Context(), run.ID, b.Step, p.Subject, b.Reason)
	switch {
	case errors.Is(err, store.ErrSelfApproval), errors.Is(err, store.ErrTwoSteps):
		writeErr(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, store.ErrNotPlanned), errors.Is(err, store.ErrStepDone), errors.Is(err, store.ErrStepNotRequired):
		writeErr(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), p.Actor(), "run.approve", "run/"+run.ID, run.Entity, map[string]any{
		"stack": st.Name, "step": b.Step, "reason": b.Reason, "plan_sha256": deref(run.PlanSHA256), "chain_complete": complete})
	if complete {
		s.notify()
	}
	run, _ = s.store.GetRun(r.Context(), run.ID)
	writeJSON(w, 200, run)
}

func (s *Server) discardRun(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	run := s.visibleRun(w, r)
	if run == nil {
		return
	}
	if !p.CanChange(run.Entity) && !p.HasEntityRole(run.Entity, identity.Manager) {
		writeErr(w, http.StatusForbidden, "discarding runs needs the developer, manager or admin role in "+run.Entity)
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Reason) > reasonMax {
		writeErr(w, 422, "reason is too long")
		return
	}
	if err := s.store.Discard(r.Context(), run.ID, "discarded by "+p.Subject+": "+b.Reason); err != nil {
		s.writeStoreErr(w, err, "only queued or planned runs can be discarded")
		return
	}
	s.audit(r.Context(), p.Actor(), "run.discard", "run/"+run.ID, run.Entity, map[string]string{"reason": b.Reason})
	run, _ = s.store.GetRun(r.Context(), run.ID)
	writeJSON(w, 200, run)
}

// ---- audit ----

// listAudit: tenant-wide roles see everything; entity members see their
// entities' events only (not tenant-wide ones).
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	evs, err := s.store.ListAudit(r.Context(), store.AuditQuery{Before: before, Limit: limit(r, 100, 500), Filter: r.URL.Query().Get("q"), Entities: visible(r)})
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, evs)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if !user(r).SeesAllEntities() {
		writeErr(w, http.StatusForbidden, "verifying the whole audit chain needs a tenant-wide role")
		return
	}
	n, broken, err := s.store.VerifyAudit(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"intact": broken == 0, "checked": n, "first_broken_id": broken})
}

// ---- runners (tenant admins) ----

func tenantAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !user(r).HasTenantRole(identity.TenantAdmin) {
		writeErr(w, http.StatusForbidden, "this needs the tenant_admin role")
		return false
	}
	return true
}

func (s *Server) listRunners(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	rs, err := s.store.ListRunners(r.Context())
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, rs)
}

func (s *Server) createRunner(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Name string `json:"name"`
		Pool string `json:"pool"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !runnerRe.MatchString(b.Name) || !poolRe.MatchString(b.Pool) {
		writeErr(w, 422, "name and pool must be lowercase letters, digits and dashes")
		return
	}
	plain, err := secure.NewToken("r")
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	rn, err := s.store.CreateRunner(r.Context(), b.Name, b.Pool, secure.HashToken(plain))
	if err != nil {
		s.writeStoreErr(w, err, "a runner with that name exists")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "runner.create", "runner/"+rn.Name, "", map[string]string{"pool": rn.Pool})
	writeJSON(w, 201, map[string]any{"runner": rn, "secret": plain})
}

func (s *Server) revokeRunner(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.store.RevokeRunner(r.Context(), id); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "runner.revoke", "runner/"+id, "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func limit(r *http.Request, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
