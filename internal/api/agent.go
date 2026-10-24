package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/cost"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/opapolicy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/redact"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/risk"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

const (
	runTokenTTL  = 2 * time.Hour
	oidcTokenTTL = time.Hour
	maxPlanBytes = 64 << 20
	maxLogBytes  = 512 << 10
)

// Job is everything a runner needs for one phase of one run.
type Job struct {
	RunID       string            `json:"run_id"`
	StackID     string            `json:"stack_id"`
	Stack       string            `json:"stack"`
	Environment string            `json:"environment"`
	Operation   string            `json:"operation"` // apply | destroy
	Phase       string            `json:"phase"`     // plan | apply
	RunToken    string            `json:"run_token"`
	Files       map[string][]byte `json:"files"`
	Providers   []string          `json:"providers"`
	TofuVersion string            `json:"tofu_version"`
	OIDCToken   string            `json:"oidc_token,omitempty"`
	PlanSHA256  string            `json:"plan_sha256,omitempty"`
	Catalog     JobCatalog        `json:"catalog"` // used by runners that do not pin their own catalog
	// Phase-specific cloud identity: plan and apply may use different roles.
	CloudEnv   map[string]string `json:"cloud_env,omitempty"`
	CloudFiles map[string][]byte `json:"cloud_files,omitempty"`
}

type JobCatalog struct {
	Modules   []*catalog.Module  `json:"modules"`
	Providers []catalog.Provider `json:"providers"`
}

// claim long-polls for up to 20 seconds and returns 204 when there is no work.
func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	rn := who(r).Runner
	deadline := time.After(20 * time.Second)
	for {
		tok, err := secure.NewToken("t")
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		run, err := s.store.ClaimRun(r.Context(), rn.ID, rn.Pool, secure.HashToken(tok), runTokenTTL)
		if err == nil {
			s.startJob(w, r, run, tok)
			return
		}
		if !errors.Is(err, store.ErrNotFound) {
			s.writeStoreErr(w, err, "")
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-s.wakeCh():
		case <-time.After(3 * time.Second): // other control plane replicas may queue work
		}
	}
}

func (s *Server) startJob(w http.ResponseWriter, r *http.Request, run *store.Run, tok string) {
	ctx := r.Context()
	phase := "plan"
	if run.Status == "applying" {
		phase = "apply"
	}
	fail := func(msg string) {
		s.store.FinishRun(ctx, run.ID, "failed", msg)
		s.engine.Finished(ctx, run.ID)
		s.audit(ctx, who(r).Subject(), "run.failed", "run/"+run.ID, run.BU, map[string]string{"error": msg})
		w.WriteHeader(http.StatusNoContent)
	}
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil {
		fail("stack not found")
		return
	}
	env, err := s.store.GetEnvironment(ctx, st.EnvironmentID)
	if err != nil {
		fail("environment not found")
		return
	}
	gen, cloud, probs := s.build(ctx, st.Name, st.BU, env, runSpec(st, run))
	if probs != nil {
		fail("stack no longer validates: " + probs[0])
		return
	}
	if gen.Hash != run.ConfigHash {
		fail("the generated configuration changed after the run was queued or planned")
		return
	}
	job := Job{
		RunID: run.ID, StackID: st.ID, Stack: st.Name, Environment: env.Name, Operation: run.Operation, Phase: phase,
		RunToken: tok, Files: gen.Files, Providers: gen.Providers, TofuVersion: s.cfg.TofuVersion,
		Catalog: JobCatalog{Modules: s.catalog.Modules, Providers: s.catalog.Providers},
	}
	if phase == "apply" {
		job.PlanSHA256 = deref(run.PlanSHA256)
	}
	job.CloudEnv, job.CloudFiles = cloud.PhaseCredentials(st.Name, phase)
	if cloud.NeedsOIDCToken() {
		job.OIDCToken, err = s.issuer.Sign(oidc.Claims{
			Subject: oidc.Subject(env.Entity, env.Name, st.Name, phase), Audience: cloud.Audience(),
			Entity: env.Entity, Environment: env.Name, Stack: st.Name, RunID: run.ID, Phase: phase, TTL: oidcTokenTTL,
		}, time.Now())
		if err != nil {
			fail("could not issue the run's OIDC token")
			return
		}
	}
	s.audit(ctx, who(r).Subject(), "run.claim", "run/"+run.ID, run.BU, map[string]any{"phase": phase, "stack": st.Name, "oidc": cloud.NeedsOIDCToken()})
	writeJSON(w, 200, job)
}

var serverRedactor = redact.New()

func (s *Server) agentLogs(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxLogBytes))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "log chunk too large")
		return
	}
	// Runners redact before sending; this second pass catches anything secret-shaped.
	if err := s.store.AppendLog(r.Context(), who(r).Run.ID, serverRedactor.String(string(bytes.ToValidUTF8(b, []byte("?"))))); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type planUpload struct {
	Summary policy.Summary `json:"summary"`
	Plan    []byte         `json:"plan"`
	SHA256  string         `json:"sha256"`
}

func (s *Server) agentPlan(w http.ResponseWriter, r *http.Request) {
	run := who(r).Run
	if run.Status != "planning" {
		writeErr(w, http.StatusConflict, "run is not planning")
		return
	}
	var up planUpload
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPlanBytes*4/3+(1<<20)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&up); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid plan upload")
		return
	}
	if secure.SHA256Hex(up.Plan) != up.SHA256 {
		writeErr(w, http.StatusBadRequest, "plan checksum mismatch")
		return
	}
	ctx := r.Context()
	st, err := s.store.GetStack(ctx, run.StackID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	env, err := s.store.GetEnvironment(ctx, st.EnvironmentID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if run.Operation == "drift" {
		s.recordDrift(w, r, run, st, up)
		return
	}
	res := policy.Evaluate(up.Summary, policy.Limits{MaxDestroys: env.MaxDestroys, MaxCreates: env.MaxCreates, MaxImports: env.MaxImports, AllowDestroy: env.AllowDestroy, Destroying: run.Operation == "destroy"})
	if sets := s.tenantPolicies(ctx, run); len(sets) > 0 {
		for _, v := range opapolicy.Evaluate(ctx, sets, s.policyInput(run, env, up.Summary)) {
			res.Violations = append(res.Violations, v)
			if v.Level == "hard" {
				res.Passed = false
			}
		}
	}
	status := "planned"
	switch {
	case !res.Passed:
		status = "policy_failed"
	case !up.Summary.HasChanges():
		status = "no_changes"
	}
	est := cost.Of(up.Summary)
	rk := risk.ClassifyWith(up.Summary, run.Operation, env.Tier, est.MonthlyDelta, s.riskSettings(ctx))
	var sealed []byte
	var object string
	if status == "planned" {
		if sealed, err = s.sealer.Seal(up.Plan, planAAD(run.ID, up.SHA256)); err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		if s.objects != nil {
			object = planKey(run.ID)
			if err := s.objects.Put(ctx, object, sealed); err != nil {
				s.log.Error("storing plan in bucket", "err", err)
				writeErr(w, http.StatusServiceUnavailable, "could not store the plan")
				return
			}
			sealed = nil
		}
	}
	_, serial, err := s.store.CurrentState(ctx, st.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	summary, _ := json.Marshal(up.Summary)
	pol, _ := json.Marshal(res)
	rkj, _ := json.Marshal(rk)
	cj, _ := json.Marshal(est)
	if err := s.store.SetPlanned(ctx, run.ID, store.Planned{Status: status, Sealed: sealed, SHA256: up.SHA256, Summary: summary,
		Policy: pol, Risk: rkj, Cost: cj, Object: object, Required: rk.Steps, Serial: serial}); err != nil {
		s.writeStoreErr(w, err, "run is not planning")
		return
	}
	s.audit(ctx, who(r).Subject(), "run.planned", "run/"+run.ID, run.BU, map[string]any{
		"status": status, "add": up.Summary.Add, "change": up.Summary.Change, "destroy": up.Summary.Destroy, "replace": up.Summary.Replace,
		"policy_passed": res.Passed, "violations": len(res.Violations), "plan_sha256": up.SHA256, "state_serial": serial,
		"risk": rk.Level, "required_approvals": rk.Steps, "monthly_cost_delta_usd": est.MonthlyDelta,
	})
	s.engine.Planned(ctx, run.ID, status == "planned")
	if status == "planned" && run.PRNumber != nil {
		// The pull request may have been closed, or got new commits, while this
		// plan was being made: such a plan must never be approved.
		if pr, err := s.store.GetPR(ctx, *run.PRNumber); err == nil && (pr.State != "open" || pr.HeadSHA != deref(run.PRSha)) {
			if moved, _ := s.store.Expire(ctx, run.ID, []string{"planned"}, "discarded", "the pull request was closed or has newer commits"); moved {
				s.engine.Finished(ctx, run.ID)
				status = "discarded"
			}
		}
	}
	if status == "planned" {
		s.autoApplyLowRisk(ctx, run, rk)
	}
	if cur, err := s.store.GetRun(ctx, run.ID); err == nil {
		changes := fmt.Sprintf("+%d ~%d -%d (replace %d), %s risk, cost %+.2f USD/month", up.Summary.Add, up.Summary.Change, up.Summary.Destroy, up.Summary.Replace, rk.Level, est.MonthlyDelta)
		switch {
		case status == "policy_failed":
			s.notifyRun(ctx, cur, "run.policy_failed", "error", "Blocked by policy: "+cur.StackName, fmt.Sprintf("%d violation(s). %s", len(res.Violations), changes), nil)
		case status == "no_changes":
			s.notifyRun(ctx, cur, "run.no_changes", "info", "No changes: "+cur.StackName, "The plan matches the deployed infrastructure.", nil)
		case cur.Status == "discarded":
			// superseded pull-request plan: nothing to announce
		case cur.Status == "apply_queued":
			s.notifyRun(ctx, cur, "run.auto_approved", "info", "Auto-approved (low risk): "+cur.StackName, changes, nil)
		default:
			s.notifyRun(ctx, cur, "run.awaiting_approval", "action", fmt.Sprintf("Approval needed: %s in %s", cur.StackName, cur.Environment),
				changes+". Needs "+strings.Join(rk.Steps, ", ")+".", rk.Steps)
		}
	}
	if status == "no_changes" {
		s.adoptPRSpec(ctx, run) // nothing to deploy: the pull request's spec already matches reality
	}
	writeJSON(w, 200, map[string]any{"status": status, "risk": rk.Level, "required_approvals": rk.Steps})
}

// recordDrift ends a refresh-only run as drifted or no_drift. Nothing is
// applied; with auto-remediation a normal plan is queued, which then needs the
// usual risk-based approvals.
func (s *Server) recordDrift(w http.ResponseWriter, r *http.Request, run *store.Run, st *store.Stack, up planUpload) {
	ctx := r.Context()
	status := "no_drift"
	if len(up.Summary.Drift) > 0 {
		status = "drifted"
	}
	_, serial, _ := s.store.CurrentState(ctx, st.ID)
	summary, _ := json.Marshal(up.Summary)
	if err := s.store.SetPlanned(ctx, run.ID, store.Planned{Status: status, SHA256: up.SHA256, Summary: summary,
		Policy: []byte(`{"passed":true,"violations":[]}`), Required: []string{}, Serial: serial}); err != nil {
		s.writeStoreErr(w, err, "run is not planning")
		return
	}
	var drifted []string
	for _, d := range up.Summary.Drift {
		drifted = append(drifted, d.Address)
	}
	s.audit(ctx, who(r).Subject(), "run.drift", "run/"+run.ID, run.BU, map[string]any{"stack": st.Name, "status": status, "resources": drifted})
	if status == "drifted" {
		s.notifyRun(ctx, run, "drift.detected", "warning", "Drift detected: "+st.Name, fmt.Sprintf("%d resource(s) changed outside OpenTofu: %s", len(drifted), strings.Join(firstN(drifted, 5), ", ")), nil)
	}
	if status == "drifted" && st.Drift.AutoRemediate {
		if env, err := s.store.GetEnvironment(ctx, st.EnvironmentID); err == nil {
			if gen, _, probs := s.build(ctx, st.Name, st.BU, env, st.Spec); probs == nil {
				if fix, err := s.store.CreateRun(ctx, st.ID, "apply", "system:drift-remediation", gen.Hash); err == nil {
					s.audit(ctx, "system:drift-remediation", "run.create", "run/"+fix.ID, st.BU, map[string]string{"stack": st.Name, "operation": "apply", "reason": "drift found by run " + run.ID})
					s.runCreated(ctx, fix.ID)
				}
			}
		}
	}
	s.engine.Planned(ctx, run.ID, false)
	writeJSON(w, 200, map[string]any{"status": status, "drifted": drifted})
}

// driftScheduler queues refresh-only runs for stacks whose check is due
// (built-in engine; with Temporal a cron workflow calls queueDueDrift).
func (s *Server) driftScheduler(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, id := range s.queueDueDrift(ctx) {
			s.runCreated(ctx, id)
		}
	}
}

func (s *Server) queueDueDrift(ctx context.Context) []string {
	ids, err := s.store.DueForDrift(ctx)
	if err != nil {
		s.log.Error("drift scheduler", "err", err)
		return nil
	}
	var runs []string
	for _, id := range ids {
		st, err := s.store.GetStack(ctx, id)
		if err != nil {
			continue
		}
		env, err := s.store.GetEnvironment(ctx, st.EnvironmentID)
		if err != nil {
			continue
		}
		gen, _, probs := s.build(ctx, st.Name, st.BU, env, st.Spec)
		if probs != nil {
			continue
		}
		if run, err := s.store.CreateRun(ctx, st.ID, "drift", "system:drift-schedule", gen.Hash); err == nil {
			s.audit(ctx, "system:drift-schedule", "run.create", "run/"+run.ID, st.BU, map[string]string{"stack": st.Name, "operation": "drift"})
			runs = append(runs, run.ID)
		}
	}
	return runs
}

func planKey(runID string) string { return "plans/" + runID + ".sealed" }

// cleanupPlans deletes bucket copies of plans whose runs have ended.
func (s *Server) cleanupPlans(ctx context.Context) {
	if s.objects == nil {
		return
	}
	ids, err := s.store.FinishedPlanObjects(ctx)
	if err != nil {
		s.log.Error("listing finished plans", "err", err)
		return
	}
	for _, id := range ids {
		if err := s.objects.Delete(ctx, planKey(id)); err != nil {
			s.log.Warn("deleting plan object", "run", id, "err", err)
		}
	}
}

func planAAD(runID, sha string) []byte { return []byte("plan:" + runID + ":" + sha) }

func (s *Server) agentGetPlan(w http.ResponseWriter, r *http.Request) {
	run := who(r).Run
	if run.Status != "applying" {
		writeErr(w, http.StatusConflict, "run is not applying")
		return
	}
	sealed, object, sha, err := s.store.PlanBlob(r.Context(), run.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if object != "" {
		if s.objects == nil {
			writeErr(w, http.StatusInternalServerError, "plan is in a bucket but no bucket is configured")
			return
		}
		if sealed, err = s.objects.Get(r.Context(), object); err != nil {
			s.log.Error("reading plan from bucket", "err", err)
			writeErr(w, http.StatusServiceUnavailable, "could not read the plan")
			return
		}
	}
	plan, err := s.sealer.Open(sealed, planAAD(run.ID, sha))
	if err != nil || secure.SHA256Hex(plan) != sha {
		s.log.Error("sealed plan failed verification", "run", run.ID)
		writeErr(w, http.StatusInternalServerError, "stored plan failed integrity verification")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Plan-SHA256", sha)
	w.Write(plan)
}

func (s *Server) agentFinish(w http.ResponseWriter, r *http.Request) {
	run := who(r).Run
	var b struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if !decode(w, r, &b) {
		return
	}
	ok := b.Status == "failed" || (b.Status == "applied" && run.Status == "applying")
	if !ok {
		writeErr(w, 422, "invalid final status for this phase")
		return
	}
	if len(b.Error) > 4000 {
		b.Error = b.Error[:4000]
	}
	b.Error = serverRedactor.String(b.Error)
	if err := s.store.FinishRun(r.Context(), run.ID, b.Status, b.Error); err != nil {
		s.writeStoreErr(w, err, "run already finished")
		return
	}
	s.engine.Finished(r.Context(), run.ID)
	if b.Status == "applied" {
		s.adoptPRSpec(r.Context(), run)
		s.notifyRun(r.Context(), run, "run.applied", "success", "Applied: "+run.StackName, "Applied in "+run.Environment+".", nil)
	} else {
		s.notifyRun(r.Context(), run, "run.failed", "error", "Failed: "+run.StackName, serverRedactor.String(firstLine(b.Error)), nil)
	}
	s.cleanupPlans(context.WithoutCancel(r.Context()))
	s.audit(r.Context(), who(r).Subject(), "run."+b.Status, "run/"+run.ID, run.BU, map[string]string{"stack": run.StackName, "error": b.Error})
	w.WriteHeader(http.StatusNoContent)
}

// state implements OpenTofu's HTTP backend for one stack. Reads and locks are
// allowed while planning; writes only while applying the approved plan.
func (s *Server) state(w http.ResponseWriter, r *http.Request) {
	run, ok := s.runFromRequest(r)
	stackID := r.PathValue("stack")
	if !ok || run.StackID != stackID {
		ip := clientIP(r)
		if s.limiter.Blocked(ip) {
			writeErr(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		s.limiter.Fail(ip)
		writeErr(w, http.StatusUnauthorized, "a valid run token for this stack is required")
		return
	}
	ctx := r.Context()
	actor := "run:" + run.ID
	switch r.Method {
	case http.MethodGet:
		ref, err := s.store.LatestState(ctx, stackID)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		data := ref.Data
		if ref.Object != "" {
			if s.objects == nil {
				writeErr(w, http.StatusInternalServerError, "state is in a bucket but no bucket is configured")
				return
			}
			if data, err = s.objects.Get(ctx, ref.Object); err != nil || secure.SHA256Hex(data) != ref.SHA256 {
				s.log.Error("state object missing or altered", "stack", stackID, "err", err)
				writeErr(w, http.StatusInternalServerError, "stored state failed integrity verification")
				return
			}
		}
		if ref.Serial == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	case http.MethodPost:
		if run.Status != "applying" {
			writeErr(w, http.StatusForbidden, "state can only be written while applying an approved plan")
			return
		}
		lockID, holder, err := s.store.LockHolder(ctx, stackID)
		if err != nil || holder == nil || *holder != run.ID || r.URL.Query().Get("ID") != lockID {
			writeErr(w, http.StatusLocked, "state must be locked by this run before writing")
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPlanBytes))
		if err != nil || !json.Valid(data) {
			writeErr(w, http.StatusBadRequest, "state must be a JSON document under 64 MiB")
			return
		}
		sha := secure.SHA256Hex(data)
		var object string
		if s.objects != nil {
			object = "state/" + stackID + "/" + sha + ".tfstate" // content-addressed: rewrites are idempotent
			if err := s.objects.Put(ctx, object, data); err != nil {
				s.log.Error("storing state in bucket", "err", err)
				writeErr(w, http.StatusServiceUnavailable, "could not store state")
				return
			}
			data = nil
		}
		serial, err := s.store.PutState(ctx, stackID, run.ID, data, object, sha)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(ctx, actor, "state.write", "stack/"+run.StackName, run.BU, map[string]any{"serial": serial, "sha256": sha, "bytes": len(data)})
		w.WriteHeader(http.StatusOK)
	case "LOCK":
		info, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		var li struct{ ID string }
		if err != nil || json.Unmarshal(info, &li) != nil || li.ID == "" {
			writeErr(w, http.StatusBadRequest, "invalid lock request")
			return
		}
		cur, err := s.store.Lock(ctx, stackID, li.ID, run.ID, info)
		if errors.Is(err, store.ErrConflict) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusLocked)
			w.Write(cur)
			return
		}
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	case "UNLOCK":
		info, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		var li struct{ ID string }
		json.Unmarshal(info, &li)
		if err := s.store.Unlock(ctx, stackID, li.ID); err != nil && !errors.Is(err, store.ErrConflict) {
			s.writeStoreErr(w, err, "")
			return
		} else if err != nil {
			writeErr(w, http.StatusConflict, "lock is not held with that ID")
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.Header().Set("Allow", "GET, POST, LOCK, UNLOCK")
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// adoptPRSpec makes a pull-request run's spec the stack's once it is deployed
// (applied, or planned with no changes), so the contracts sync after the merge
// finds nothing to change.
func (s *Server) adoptPRSpec(ctx context.Context, run *store.Run) {
	if len(run.Spec) == 0 {
		return
	}
	n := 0
	if run.PRNumber != nil {
		n = *run.PRNumber
	}
	ref := "pr#" + strconv.Itoa(n) + "@" + short(deref(run.PRSha))
	if err := s.store.AdoptPRSpec(ctx, run.StackID, run.Spec, ref); err != nil {
		s.log.Error("recording the pull request spec failed", "run", run.ID, "err", err)
	}
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return append(xs[:n:n], fmt.Sprintf("and %d more", len(xs)-n))
	}
	return xs
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
