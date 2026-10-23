package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/cost"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
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
		s.audit(ctx, who(r).Subject(), "run.failed", "run/"+run.ID, run.Entity, map[string]string{"error": msg})
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
	gen, cloud, probs := s.build(ctx, st.Name, env, st.Spec)
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
	if cloud.NeedsOIDCToken() {
		job.OIDCToken, err = s.issuer.Sign(oidc.Claims{
			Subject: oidc.Subject(env.Name, st.Name, phase), Audience: cloud.Audience(),
			Environment: env.Name, Stack: st.Name, RunID: run.ID, Phase: phase, TTL: oidcTokenTTL,
		}, time.Now())
		if err != nil {
			fail("could not issue the run's OIDC token")
			return
		}
	}
	s.audit(ctx, who(r).Subject(), "run.claim", "run/"+run.ID, run.Entity, map[string]any{"phase": phase, "stack": st.Name, "oidc": cloud.NeedsOIDCToken()})
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
	res := policy.Evaluate(up.Summary, policy.Limits{MaxDestroys: env.MaxDestroys, AllowDestroy: env.AllowDestroy, Destroying: run.Operation == "destroy"})
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
	if status == "planned" {
		if sealed, err = s.sealer.Seal(up.Plan, planAAD(run.ID, up.SHA256)); err != nil {
			s.writeStoreErr(w, err, "")
			return
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
		Policy: pol, Risk: rkj, Cost: cj, Required: rk.Steps, Serial: serial}); err != nil {
		s.writeStoreErr(w, err, "run is not planning")
		return
	}
	s.audit(ctx, who(r).Subject(), "run.planned", "run/"+run.ID, run.Entity, map[string]any{
		"status": status, "add": up.Summary.Add, "change": up.Summary.Change, "destroy": up.Summary.Destroy, "replace": up.Summary.Replace,
		"policy_passed": res.Passed, "violations": len(res.Violations), "plan_sha256": up.SHA256, "state_serial": serial,
		"risk": rk.Level, "required_approvals": rk.Steps, "monthly_cost_delta_usd": est.MonthlyDelta,
	})
	writeJSON(w, 200, map[string]any{"status": status, "risk": rk.Level, "required_approvals": rk.Steps})
}

func planAAD(runID, sha string) []byte { return []byte("plan:" + runID + ":" + sha) }

func (s *Server) agentGetPlan(w http.ResponseWriter, r *http.Request) {
	run := who(r).Run
	if run.Status != "applying" {
		writeErr(w, http.StatusConflict, "run is not applying")
		return
	}
	sealed, sha, err := s.store.PlanBlob(r.Context(), run.ID)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
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
	s.audit(r.Context(), who(r).Subject(), "run."+b.Status, "run/"+run.ID, run.Entity, map[string]string{"stack": run.StackName, "error": b.Error})
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
		data, _, err := s.store.CurrentState(ctx, stackID)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		if data == nil {
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
		serial, err := s.store.PutState(ctx, stackID, run.ID, data, sha)
		if err != nil {
			s.writeStoreErr(w, err, "")
			return
		}
		s.audit(ctx, actor, "state.write", "stack/"+run.StackName, run.Entity, map[string]any{"serial": serial, "sha256": sha, "bytes": len(data)})
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
