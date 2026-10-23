package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/contracts"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/risk"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

const (
	contractsKey       = "contracts"
	contractsTokenKey  = "contracts_token"
	contractsStatusKey = "contracts_status"
	tokenAAD           = "contracts-token"
)

// SyncResult is what happened to one contract in a sync.
type SyncResult struct {
	File   string `json:"file,omitempty"`
	Stack  string `json:"stack,omitempty"`
	Action string `json:"action"` // created | updated | unchanged | waiting | error | orphaned
	RunID  string `json:"run_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

type SyncStatus struct {
	Revision string       `json:"revision"`
	SyncedAt time.Time    `json:"synced_at"`
	Error    string       `json:"error,omitempty"`
	Results  []SyncResult `json:"results"`
}

var syncMu sync.Mutex

func (s *Server) contractsConfig(ctx context.Context) (*contracts.Config, bool) {
	var c contracts.Config
	ok, err := s.store.Setting(ctx, contractsKey, &c)
	if err != nil || !ok {
		return nil, false
	}
	return &c, true
}

func (s *Server) getContracts(w http.ResponseWriter, r *http.Request) {
	cfg, _ := s.contractsConfig(r.Context())
	var tok map[string]string
	hasToken, _ := s.store.Setting(r.Context(), contractsTokenKey, &tok)
	var st SyncStatus
	s.store.Setting(r.Context(), contractsStatusKey, &st)
	writeJSON(w, 200, map[string]any{"config": cfg, "token_set": hasToken, "status": st})
}

func (s *Server) putContracts(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var c contracts.Config
	if !decode(w, r, &c) {
		return
	}
	if err := c.Validate(s.cfg.AllowLocalContracts); err != nil {
		writeErr(w, 422, "invalid contracts repository", errLines(err)...)
		return
	}
	if err := s.store.PutSetting(r.Context(), contractsKey, c, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "contracts.configure", "contracts", "", c)
	writeJSON(w, 200, c)
}

// putContractsToken stores the Git access token sealed with the tenant's master
// key. It is never returned by any API.
func (s *Server) putContractsToken(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Token) < 8 || len(b.Token) > 512 || strings.ContainsAny(b.Token, " \n\r\t") {
		writeErr(w, 422, "token must be 8-512 characters without whitespace")
		return
	}
	sealed, err := s.sealer.Seal([]byte(b.Token), []byte(tokenAAD))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	if err := s.store.PutSetting(r.Context(), contractsTokenKey, map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)}, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "contracts.token", "contracts", "", map[string]bool{"set": true})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) contractsToken(ctx context.Context) string {
	var t map[string]string
	if ok, _ := s.store.Setting(ctx, contractsTokenKey, &t); !ok {
		return ""
	}
	sealed, err := base64.StdEncoding.DecodeString(t["sealed"])
	if err != nil {
		return ""
	}
	pt, err := s.sealer.Open(sealed, []byte(tokenAAD))
	if err != nil {
		return ""
	}
	return string(pt)
}

func (s *Server) syncContractsNow(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	st, err := s.syncContracts(r.Context(), true)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, 200, st)
}

// contractsSyncer polls the contracts repository (pull-based).
func (s *Server) contractsSyncer(ctx context.Context) {
	last := time.Time{}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cfg, ok := s.contractsConfig(ctx)
		if !ok || !cfg.Enabled || time.Since(last) < time.Duration(cfg.PollSeconds)*time.Second {
			continue
		}
		last = time.Now()
		if _, err := s.syncContracts(ctx, false); err != nil {
			s.log.Warn("contracts sync failed", "err", err)
		}
	}
}

// syncContracts brings Git-managed stacks in line with the repository's branch.
func (s *Server) syncContracts(ctx context.Context, force bool) (*SyncStatus, error) {
	syncMu.Lock()
	defer syncMu.Unlock()
	cfg, ok := s.contractsConfig(ctx)
	if !ok {
		return nil, errors.New("no contracts repository is configured")
	}
	var prev SyncStatus
	s.store.Setting(ctx, contractsStatusKey, &prev)
	src, err := contracts.New(*cfg, s.contractsToken(ctx), nil)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*SyncStatus, error) {
		st := SyncStatus{Revision: prev.Revision, SyncedAt: time.Now(), Error: err.Error(), Results: prev.Results}
		s.store.PutSetting(ctx, contractsStatusKey, st, "system:contracts")
		return nil, err
	}
	rev, err := src.Revision(ctx)
	if err != nil {
		return fail(err)
	}
	if rev == prev.Revision && prev.Error == "" && !force {
		return &prev, nil
	}
	files, err := src.Files(ctx, rev)
	if err != nil {
		return fail(err)
	}
	actor := "git:" + cfg.Repo + "@" + rev[:7]
	cs, problems := contracts.Parse(files, cfg.Path)
	st := SyncStatus{Revision: rev, SyncedAt: time.Now(), Results: []SyncResult{}}
	for f, msg := range problems {
		st.Results = append(st.Results, SyncResult{File: f, Action: "error", Error: msg})
	}
	seen := map[string]bool{}
	for _, c := range cs {
		seen[c.Name] = true
		st.Results = append(st.Results, s.applyContract(ctx, cfg, c, rev, actor))
	}
	if all, err := s.store.ListStacks(ctx, nil); err == nil {
		for _, x := range all {
			if x.ManagedBy == "git" && !seen[x.Name] {
				st.Results = append(st.Results, SyncResult{Stack: x.Name, Action: "orphaned",
					Error: "removed from the repository; the stack and its resources are kept until someone plans a destroy"})
			}
		}
	}
	counts := map[string]int{}
	for _, r := range st.Results {
		counts[r.Action]++
	}
	s.store.PutSetting(ctx, contractsStatusKey, st, "system:contracts")
	s.audit(ctx, actor, "contracts.sync", "contracts", "", map[string]any{"revision": rev, "results": counts})
	return &st, nil
}

func (s *Server) applyContract(ctx context.Context, cfg *contracts.Config, c contracts.Contract, rev, actor string) SyncResult {
	res := SyncResult{File: c.File, Stack: c.Name}
	errOut := func(msg string) SyncResult { res.Action, res.Error = "error", msg; return res }
	env, err := s.store.GetEnvironment(ctx, c.Environment)
	if err != nil {
		return errOut("unknown environment " + c.Environment)
	}
	gen, _, probs := s.build(ctx, c.Name, env, c.Spec)
	if probs != nil {
		return errOut(strings.Join(probs, "; "))
	}
	spec := normalizeSpec(c.Spec)
	existing, err := s.store.GetStack(ctx, c.Name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		st, err := s.store.CreateManagedStack(ctx, c.Name, env.BU, env.Entity, env.ID, spec, actor, "git", rev)
		if err != nil {
			return errOut("could not create the stack: " + err.Error())
		}
		s.audit(ctx, actor, "stack.create", "stack/"+st.Name, st.BU, map[string]any{"environment": env.Name, "spec": st.Spec, "source_ref": rev})
		res.Action = "created"
		existing = st
	case err != nil:
		return errOut(err.Error())
	case existing.ManagedBy != "git":
		return errOut("a stack with this name exists and is managed in the UI")
	case existing.EnvironmentID != env.ID:
		return errOut("a stack cannot move to another environment; use a new name")
	case sameJSON(existing.Spec, spec):
		res.Action = "unchanged"
		return res
	default:
		if err := s.store.UpdateGitStack(ctx, existing.ID, spec, rev); err != nil {
			res.Action, res.Error = "waiting", "the stack has an active run; the change is applied on a later sync"
			return res
		}
		s.audit(ctx, actor, "stack.update", "stack/"+existing.Name, existing.BU, map[string]any{"before": existing.Spec, "after": json.RawMessage(spec), "source_ref": rev})
		res.Action = "updated"
	}
	if cfg.AutoPlan {
		if run, err := s.store.CreateRun(ctx, existing.ID, "apply", actor, gen.Hash); err == nil {
			res.RunID = run.ID
			s.audit(ctx, actor, "run.create", "run/"+run.ID, existing.BU, map[string]string{"stack": existing.Name, "operation": "apply", "source_ref": rev})
			s.notify()
		}
	}
	return res
}

// autoApplyLowRisk signs every approval step of a low-risk run that came from
// the contracts repository, when the tenant opted in. The system signs each
// step under its own name so the audit trail shows exactly what happened.
func (s *Server) autoApplyLowRisk(ctx context.Context, run *store.Run, rk risk.Result) {
	if rk.Level != risk.Low || !strings.HasPrefix(run.CreatedBy, "git:") {
		return
	}
	cfg, ok := s.contractsConfig(ctx)
	if !ok || !cfg.AutoApplyLowRisk {
		return
	}
	for _, step := range rk.Steps {
		approver := "system:auto-deploy:" + step
		complete, err := s.store.Approve(ctx, run.ID, step, approver, "low-risk change from the contracts repository")
		if err != nil {
			s.log.Warn("auto-approve failed", "run", run.ID, "err", err)
			return
		}
		s.audit(ctx, approver, "run.approve", "run/"+run.ID, run.BU, map[string]any{"step": step, "auto": true, "chain_complete": complete})
		if complete {
			s.notify()
		}
	}
}

func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return bytes.Equal(xa, ya)
}
