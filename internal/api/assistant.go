package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/assistant"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
)

const assistantTimeout = 5 * time.Minute

// enableAssistant turns the assistant on when an API key is configured.
func (s *Server) enableAssistant() error {
	if s.cfg.AssistantAPIKey == "" {
		return nil
	}
	extra, err := assistant.DirDocs(s.cfg.AssistantDocsDir)
	if err != nil {
		return fmt.Errorf("PRAVAHA_ASSISTANT_DOCS_DIR: %w", err)
	}
	s.assistantDocs = append(append(assistant.CatalogDocs(s.catalog), assistant.GuideDocs()...), extra...)
	s.assistant = assistant.New(assistant.Config{
		APIKey: s.cfg.AssistantAPIKey, BaseURL: s.cfg.AssistantBaseURL, Model: s.cfg.AssistantModel,
		Effort: s.cfg.AssistantEffort, Fallbacks: s.cfg.AssistantFallbacks,
	})
	s.log.Info("assistant enabled: questions and retrieved passages are sent to the Anthropic API",
		"model", s.cfg.AssistantModel, "passages", len(s.assistantDocs))
	return nil
}

func (s *Server) assistantInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"enabled": s.assistant != nil, "model": s.cfg.AssistantModel})
}

// askAssistant streams newline-delimited JSON: {"type":"status"} events while
// the assistant works, then one {"type":"answer"} or {"type":"error"}.
func (s *Server) askAssistant(w http.ResponseWriter, r *http.Request) {
	if s.assistant == nil {
		writeErr(w, http.StatusNotFound, assistant.ErrDisabled.Error())
		return
	}
	p := user(r)
	if s.askLimiter.Blocked(p.Subject) {
		writeErr(w, http.StatusTooManyRequests, "too many assistant questions; try again later")
		return
	}
	var b struct {
		Question string           `json:"question"`
		History  []assistant.Turn `json:"history"`
	}
	if !decode(w, r, &b) {
		return
	}
	if q := strings.TrimSpace(b.Question); q == "" || len(q) > 4000 {
		writeErr(w, 422, "the question must be 1 to 4000 characters")
		return
	}
	s.askLimiter.Fail(p.Subject) // counts every question
	ctx, cancel := context.WithTimeout(r.Context(), assistantTimeout)
	defer cancel()

	ix, envs, err := s.assistantCorpus(ctx, r)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Now().Add(assistantTimeout + 30*time.Second))
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	enc := json.NewEncoder(w)
	emit := func(v any) {
		enc.Encode(v)
		rc.Flush()
	}
	emit(map[string]string{"type": "status", "text": fmt.Sprintf("Searching %d passages", ix.Len())})

	ans, err := s.assistant.Ask(ctx, assistant.Request{
		Question: b.Question, History: b.History, Index: ix, Environments: envs,
		Validate: func(ctx context.Context, name, bu, envName string, raw json.RawMessage) []string {
			return s.validateDraft(ctx, r, name, bu, envName, raw)
		},
		Progress: func(t string) { emit(map[string]string{"type": "status", "text": t}) },
	})
	sum := sha256.Sum256([]byte(b.Question))
	meta := map[string]any{"question_sha256": hex.EncodeToString(sum[:]), "question_chars": len(b.Question)}
	if err != nil {
		s.log.Warn("assistant request failed", "err", err)
		meta["error"] = true
		s.audit(r.Context(), p.Actor(), "assistant.ask", "assistant", "", meta)
		emit(map[string]string{"type": "error", "error": "the assistant could not answer right now"})
		return
	}
	meta["model_calls"], meta["input_tokens"], meta["output_tokens"] = ans.Usage.ModelCalls, ans.Usage.InputTokens, ans.Usage.OutputTokens
	meta["sources"] = len(ans.Sources)
	if ans.Draft != nil {
		meta["draft_environment"] = ans.Draft.Environment
	}
	s.audit(r.Context(), p.Actor(), "assistant.ask", "assistant", "", meta)
	emit(map[string]any{"type": "answer", "answer": ans})
}

// assistantCorpus is the static knowledge plus what this caller may see:
// stacks and environments in their visible BUs, the tenant's policies and the
// risk policy (both readable by every member).
func (s *Server) assistantCorpus(ctx context.Context, r *http.Request) (*assistant.Index, []assistant.Environment, error) {
	p := user(r)
	var docs []assistant.Doc
	var envs []assistant.Environment
	es, err := s.store.ListEnvironments(ctx, p.VisibleEntities())
	if err != nil {
		return nil, nil, err
	}
	for _, e := range es {
		cloud, region := "unknown", ""
		if c, err := spec.DecodeCloud(e.Cloud); err == nil {
			cloud = c.Provider
			switch {
			case c.AWS != nil:
				region = c.AWS.Region
			case c.GCP != nil:
				region = c.GCP.Region + ", project " + c.GCP.ProjectID
			}
		}
		bus := p.WritableBUs(e.Entity)
		writable := len(bus) > 0
		envs = append(envs, assistant.Environment{Name: e.Name, Entity: e.Entity, WritableBUs: bus, Tier: e.Tier, Cloud: cloud, Writable: writable})
		docs = append(docs, assistant.Doc{ID: "environment:" + e.Name, Kind: "environment", Title: "Environment " + e.Name,
			Text: fmt.Sprintf("Environment %q of entity (product) %s, shared by all its business units: tier %s, cloud %s %s, connection %s, runner pool %s, destroys allowed: %v, max destroys per run: %d. Business units the person can create stacks for here: %v.",
				e.Name, e.Entity, e.Tier, cloud, region, e.Connection, e.RunnerPool, e.AllowDestroy, e.MaxDestroys, bus)})
	}
	sts, err := s.store.ListStacks(ctx, visible(r))
	if err != nil {
		return nil, nil, err
	}
	for _, st := range sts {
		var b strings.Builder
		fmt.Fprintf(&b, "Stack %q in environment %s (business unit %s), managed by %s.", st.Name, st.Environment, st.BU, st.ManagedBy)
		if st.LastRun != nil {
			lr, _ := json.Marshal(st.LastRun)
			fmt.Fprintf(&b, " Last run: %s.", lr)
		}
		if st.Drift.IntervalMinutes > 0 {
			fmt.Fprintf(&b, " Drift checks every %d minutes (auto-remediate: %v).", st.Drift.IntervalMinutes, st.Drift.AutoRemediate)
		}
		fmt.Fprintf(&b, "\nSpec: %s", st.Spec)
		docs = append(docs, assistant.Doc{ID: "stack:" + st.Name, Kind: "stack", Title: "Stack " + st.Name, Text: b.String()})
	}
	ps, err := s.store.ListPolicySets(ctx)
	if err != nil {
		return nil, nil, err
	}
	for _, pol := range ps {
		docs = append(docs, assistant.Doc{ID: "policy:" + pol.Name, Kind: "policy", Title: "Policy set " + pol.Name,
			Text: fmt.Sprintf("OPA policy set %q, level %s (hard blocks runs, advisory only warns), scope %q, enabled %v:\n%s", pol.Name, pol.Level, pol.Scope, pol.Enabled, pol.Module)})
	}
	rs, _ := json.Marshal(s.riskSettings(ctx))
	docs = append(docs, assistant.Doc{ID: "settings:risk", Kind: "settings", Title: "Risk policy",
		Text: "This tenant's risk policy (approval steps per risk level, the risk of production changes, cost thresholds): " + string(rs)})
	return assistant.NewIndex(s.assistantDocs, docs), envs, nil
}

// validateDraft runs the same checks as creating the stack, without saving.
func (s *Server) validateDraft(ctx context.Context, r *http.Request, name, bu, envName string, raw json.RawMessage) []string {
	var probs []string
	if !spec.StackNameRe.MatchString(name) {
		probs = append(probs, "the stack name must be lowercase letters, digits and dashes")
		name = "draft"
	}
	p := user(r)
	if !p.CanChange(bu) {
		return append(probs, fmt.Sprintf("the person cannot create stacks in business unit %q", bu))
	}
	env, err := s.store.EntityEnvironment(ctx, p.EntityOf(bu), envName)
	if err != nil {
		return append(probs, fmt.Sprintf("business unit %s's entity has no environment %q", bu, envName))
	}
	if _, _, more := s.build(ctx, name, bu, env, raw); more != nil {
		probs = append(probs, more...)
	}
	return probs
}
