package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/contracts"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/cost"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/githubapp"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/risk"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// Pull-request plans (apply before merge).
//
// When a pull request against the contracts branch changes contracts, every
// changed stack gets a run that plans the pull request's version of its spec.
// The pull request shows one comment summarising the plans and a
// "pravaha/apply" commit status. Runs go through the usual risk-based
// approvals; each applies exactly the pull request's spec. When every changed
// stack has applied, the status turns green and the platform merges the pull
// request, so the branch only ever holds what is deployed. A new commit replans;
// closing the pull request discards its plans. Require the "pravaha/apply"
// status in branch protection so nobody merges before the apply.

const prStatusContext = "pravaha/apply"

// PRResult is what happened to one contract of a pull request.
type PRResult struct {
	File   string `json:"file,omitempty"`
	Stack  string `json:"stack,omitempty"`
	BU     string `json:"bu,omitempty"`
	Env    string `json:"environment,omitempty"`
	Action string `json:"action"` // planned | unchanged | error | locked
	RunID  string `json:"run_id,omitempty"`
	Error  string `json:"error,omitempty"`
}

var prMu sync.Mutex // one pull request is processed at a time

// prContext returns the GitHub App, installation and contracts settings, when
// pull-request plans can work: a GitHub contracts repository using the app.
func (s *Server) prContext(ctx context.Context) (*githubapp.App, int64, *contracts.Config, error) {
	cfg, ok := s.contractsConfig(ctx)
	if !ok || cfg.Provider != "github" || cfg.Auth != "github_app" {
		return nil, 0, nil, errors.New("pull-request plans need a GitHub contracts repository that authenticates with the GitHub App")
	}
	app, gcfg, err := s.githubApp(ctx)
	if err != nil {
		return nil, 0, nil, err
	}
	inst := gcfg.InstallationID
	if inst == 0 {
		i, err := app.RepoInstallation(ctx, cfg.Repo)
		if err != nil {
			return nil, 0, nil, err
		}
		inst = i.ID
	}
	return app, inst, cfg, nil
}

func (s *Server) runLink(runID string) string {
	return strings.TrimRight(s.cfg.CentralURL, "/") + "/#/t/" + s.cfg.Tenant + "/runs/" + runID
}

// planPR plans every changed contract of a pull request at its head commit.
func (s *Server) planPR(ctx context.Context, number int) error {
	prMu.Lock()
	defer prMu.Unlock()
	return s.planPRLocked(ctx, number)
}

func (s *Server) planPRLocked(ctx context.Context, number int) error {
	app, inst, cfg, err := s.prContext(ctx)
	if err != nil {
		return err
	}
	pr, err := app.GetPR(ctx, inst, cfg.Repo, number)
	if err != nil {
		return err
	}
	if pr.State != "open" || pr.Base.Ref != cfg.Branch {
		return nil
	}
	// Plans for older commits are no longer wanted; discard them first so they
	// release the stack lock for the new plans.
	if runs, err := s.store.PRRuns(ctx, number); err == nil {
		for _, r := range runs {
			if r.PRSha != nil && *r.PRSha != pr.Head.SHA {
				if moved, _ := s.store.Expire(ctx, r.ID, []string{"queued", "planned"}, "discarded", "superseded by a newer commit"); moved {
					s.engine.Finished(ctx, r.ID)
				}
			}
		}
	}
	rec := &store.PullRequest{Number: number, Repo: cfg.Repo, Title: pr.Title, Author: pr.User.Login, HTMLURL: pr.HTMLURL, HeadSHA: pr.Head.SHA}
	var results []PRResult
	switch {
	case pr.Draft:
		results = []PRResult{{Action: "skipped", Error: "draft pull request: plans start when it is ready for review"}}
	case !strings.EqualFold(pr.Head.Repo.FullName, cfg.Repo):
		results = []PRResult{{Action: "skipped", Error: "pull requests from forks are not planned"}}
	default:
		results = s.planPRContracts(ctx, cfg, number, pr.Head.SHA, pr.User.Login)
	}
	rec.Results, _ = json.Marshal(results)
	if err := s.store.UpsertPR(ctx, rec); err != nil {
		return err
	}
	s.audit(ctx, "git:pr#"+fmt.Sprint(number), "pr.plan", fmt.Sprintf("pr/%d", number), "", map[string]any{"sha": pr.Head.SHA, "results": results})
	planned, problems := 0, 0
	for _, r := range results {
		switch r.Action {
		case "planned":
			planned++
		case "error", "locked":
			problems++
		}
	}
	if planned+problems > 0 {
		sev := "info"
		if problems > 0 {
			sev = "error"
		}
		s.notifyEvent(ctx, store.Notification{Kind: "pr.planned", Severity: sev, Title: fmt.Sprintf("Pull request #%d: %s", number, pr.Title),
			Body: fmt.Sprintf("%d stack(s) planning, %d problem(s); applied before merge.", planned, problems), Link: "integrations/github"})
	}
	return s.reconcilePRLocked(ctx, number)
}

func (s *Server) planPRContracts(ctx context.Context, cfg *contracts.Config, number int, sha, author string) []PRResult {
	token, err := s.githubInstallationToken(ctx, cfg.Repo)
	if err != nil {
		return []PRResult{{Action: "error", Error: err.Error()}}
	}
	src, err := contracts.New(*cfg, token, nil)
	if err != nil {
		return []PRResult{{Action: "error", Error: err.Error()}}
	}
	files, err := src.Files(ctx, sha)
	if err != nil {
		return []PRResult{{Action: "error", Error: "reading the pull request's contracts: " + err.Error()}}
	}
	cs, problems := contracts.ParseLayout(files, cfg.Path, cfg.Layout)
	results := []PRResult{}
	for f, msg := range problems {
		results = append(results, PRResult{File: f, Action: "error", Error: msg})
	}
	actor := fmt.Sprintf("git:pr#%d:%s", number, author)
	// Runs already made for this commit are reused (redeliveries, /plan while running).
	existing := map[string]*store.Run{}
	if runs, err := s.store.PRRuns(ctx, number); err == nil {
		for _, r := range runs {
			if r.PRSha != nil && *r.PRSha == sha && r.Status != "discarded" && existing[r.StackID] == nil {
				existing[r.StackID] = r
			}
		}
	}
	for _, c := range cs {
		res := PRResult{File: c.File, Stack: c.Name, BU: c.BU, Env: c.Environment}
		fail := func(msg string) { res.Action, res.Error = "error", msg; results = append(results, res) }
		if c.BU == "" {
			fail(`the contract must name its business unit ("bu")`)
			continue
		}
		entity, ok := s.buEntity(c.BU)
		if !ok {
			fail("unknown business unit " + c.BU)
			continue
		}
		if c.Entity != "" && c.Entity != entity {
			fail(fmt.Sprintf("business unit %s belongs to %s, not folder %s", c.BU, entity, c.Entity))
			continue
		}
		env, err := s.store.EntityEnvironment(ctx, entity, c.Environment)
		if err != nil {
			fail(fmt.Sprintf("entity %s has no environment %s", entity, c.Environment))
			continue
		}
		gen, _, probs := s.build(ctx, c.Name, c.BU, env, c.Spec)
		if probs != nil {
			fail(strings.Join(probs, "; "))
			continue
		}
		spec := []byte(gen.Spec)
		st, err := s.store.GetStack(ctx, c.Name)
		switch {
		case errors.Is(err, store.ErrNotFound):
			if st, err = s.store.CreateProposedStack(ctx, c.Name, c.BU, entity, env.ID, spec, actor, number); err != nil {
				fail("could not create the stack: " + err.Error())
				continue
			}
			s.audit(ctx, actor, "stack.create", "stack/"+st.Name, st.BU, map[string]any{"environment": env.Name, "proposed_by": fmt.Sprintf("pr#%d", number)})
		case err != nil:
			fail(err.Error())
			continue
		case st.ManagedBy != "git":
			fail("a stack with this name is managed in the UI")
			continue
		case st.EnvironmentID != env.ID || st.BU != c.BU:
			fail("a stack cannot move to another environment or business unit; use a new name")
			continue
		case sameJSON(st.Spec, spec) && st.PRNumber == nil:
			res.Action = "unchanged"
			results = append(results, res)
			continue
		}
		if prev := existing[st.ID]; prev != nil && prev.Status != "failed" && prev.Status != "policy_failed" {
			res.Action, res.RunID = "planned", prev.ID
			results = append(results, res)
			continue
		}
		run, err := s.store.CreatePRRun(ctx, st.ID, actor, gen.Hash, spec, number, sha)
		if errors.Is(err, store.ErrConflict) {
			res.Action, res.Error = "locked", "another run is active on this stack; comment /plan to plan again once it finishes"
			results = append(results, res)
			continue
		}
		if err != nil {
			fail(err.Error())
			continue
		}
		res.Action, res.RunID = "planned", run.ID
		s.audit(ctx, actor, "run.create", "run/"+run.ID, st.BU, map[string]any{"stack": st.Name, "operation": "apply", "pr": number, "sha": sha})
		s.runCreated(ctx, run.ID)
		results = append(results, res)
	}
	return results
}

// closePR discards a closed pull request's pending plans and removes stacks it
// proposed that were never applied. A merge is handled by the contracts sync.
func (s *Server) closePR(ctx context.Context, number int, merged bool) {
	prMu.Lock()
	defer prMu.Unlock()
	if _, err := s.store.GetPR(ctx, number); err != nil {
		return
	}
	state := "closed"
	if merged {
		state = "merged"
	}
	s.store.SetPRState(ctx, number, state)
	if merged {
		return
	}
	if runs, err := s.store.PRRuns(ctx, number); err == nil {
		for _, r := range runs {
			if moved, _ := s.store.Expire(ctx, r.ID, []string{"queued", "planned", "apply_queued"}, "discarded", "the pull request was closed"); moved {
				s.engine.Finished(ctx, r.ID)
			}
		}
	}
	if names, err := s.store.DropProposedStacks(ctx, number); err == nil && len(names) > 0 {
		s.audit(ctx, fmt.Sprintf("git:pr#%d", number), "stack.drop_proposed", fmt.Sprintf("pr/%d", number), "", map[string]any{"stacks": names})
	}
	s.audit(ctx, fmt.Sprintf("git:pr#%d", number), "pr.closed", fmt.Sprintf("pr/%d", number), "", nil)
}

// prReconciler keeps open pull requests' comments and statuses current and
// merges those whose changes are all applied.
func (s *Server) prReconciler(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		prs, err := s.store.OpenPRs(ctx)
		if err != nil || len(prs) == 0 {
			continue
		}
		prMu.Lock()
		for _, p := range prs {
			if err := s.reconcilePRLocked(ctx, p.Number); err != nil {
				s.log.Warn("pull request update failed", "pr", p.Number, "err", err)
			}
		}
		prMu.Unlock()
	}
}

type prRow struct {
	PRResult
	Run *store.Run
}

// reconcilePRLocked updates the comment and status of one pull request and
// merges it when every planned stack has applied. Callers hold prMu.
func (s *Server) reconcilePRLocked(ctx context.Context, number int) error {
	pr, err := s.store.GetPR(ctx, number)
	if err != nil || pr.State != "open" {
		return err
	}
	app, inst, cfg, err := s.prContext(ctx)
	if err != nil {
		return err
	}
	var results []PRResult
	json.Unmarshal(pr.Results, &results)
	// Self-healing: plans of older commits that finished planning are discarded,
	// and stacks that were locked by another run are planned once they are free.
	if runs, err := s.store.PRRuns(ctx, number); err == nil {
		for _, r := range runs {
			if r.PRSha != nil && *r.PRSha != pr.HeadSHA {
				if moved, _ := s.store.Expire(ctx, r.ID, []string{"queued", "planned"}, "discarded", "superseded by a newer commit"); moved {
					s.engine.Finished(ctx, r.ID)
				}
			}
		}
	}
	for _, r := range results {
		if r.Action == "locked" {
			if busy, err := s.store.StackBusy(ctx, r.Stack); err == nil && !busy {
				return s.planPRLocked(ctx, number) // replans and reconciles
			}
		}
	}
	rows := make([]prRow, 0, len(results))
	pending, failed, applied, errs := 0, 0, 0, 0
	firstRun := ""
	for _, r := range results {
		row := prRow{PRResult: r}
		switch r.Action {
		case "error", "locked":
			errs++
		case "planned":
			if run, err := s.store.GetRun(ctx, r.RunID); err == nil {
				row.Run = run
				if firstRun == "" {
					firstRun = run.ID
				}
				switch run.Status {
				case "applied", "no_changes":
					applied++
				case "failed", "policy_failed", "discarded":
					failed++
				default:
					pending++
				}
			}
		}
		rows = append(rows, row)
	}
	state, desc := "pending", ""
	switch {
	case errs > 0:
		state, desc = "failure", fmt.Sprintf("%d contract(s) cannot be planned", errs)
	case failed > 0:
		state, desc = "failure", fmt.Sprintf("%d plan(s) failed or were discarded; push a fix or comment /plan", failed)
	case pending > 0:
		state, desc = "pending", fmt.Sprintf("%d of %d stack(s) waiting for plan, approvals or apply", pending, pending+applied)
	case applied > 0:
		state, desc = "success", fmt.Sprintf("%d stack(s) applied", applied)
	default:
		state, desc = "success", "no stack changes to apply"
	}
	body := prComment(pr, rows, state, desc, s.runLink)
	sum := sha256.Sum256([]byte(state + "\x00" + desc + "\x00" + body))
	hash := hex.EncodeToString(sum[:])
	if hash != pr.CommentSum {
		target := ""
		if firstRun != "" {
			target = s.runLink(firstRun)
		}
		if err := app.SetStatus(ctx, inst, cfg.Repo, pr.HeadSHA, state, prStatusContext, desc, target); err != nil {
			return fmt.Errorf("setting the commit status: %w", err)
		}
		var cid int64
		if pr.CommentID != nil {
			cid = *pr.CommentID
		}
		cid, err = app.Comment(ctx, inst, cfg.Repo, number, cid, body)
		if err != nil {
			return fmt.Errorf("commenting: %w", err)
		}
		s.store.SetPRComment(ctx, number, cid, hash)
	}
	// Apply before merge: merge only when every planned stack applied.
	if state == "success" && applied > 0 {
		title := fmt.Sprintf("%s (#%d)", pr.Title, number)
		msg := fmt.Sprintf("Applied by Cloud Pravaha before merge: %d stack(s).", applied)
		if err := app.Merge(ctx, inst, cfg.Repo, number, pr.HeadSHA, title, msg); err != nil {
			var cid int64
			if pr.CommentID != nil {
				cid = *pr.CommentID
			}
			app.Comment(ctx, inst, cfg.Repo, number, cid, body+"\n\n> ⚠️ The changes are applied, but merging failed: "+err.Error()+". Merge manually; the branch then matches what is deployed.")
			s.store.SetPRComment(ctx, number, cid, "merge-failed")
			s.store.SetPRState(ctx, number, "applied")
			return fmt.Errorf("merging: %w", err)
		}
		s.store.SetPRState(ctx, number, "merged")
		s.audit(ctx, "system:pr-merge", "pr.merged", fmt.Sprintf("pr/%d", number), "", map[string]any{"sha": pr.HeadSHA, "applied": applied})
		s.notifyEvent(ctx, store.Notification{Kind: "pr.merged", Severity: "success", Title: fmt.Sprintf("Merged pull request #%d after apply", number),
			Body: fmt.Sprintf("%s — %d stack(s) applied, then merged.", pr.Title, applied), Link: "integrations/github"})
	}
	return nil
}

func prComment(pr *store.PullRequest, rows []prRow, state, desc string, link func(string) string) string {
	icon := map[string]string{"success": "✅", "failure": "❌", "pending": "⏳"}[state]
	var b strings.Builder
	fmt.Fprintf(&b, "### %s Cloud Pravaha: %s\n\n", icon, desc)
	fmt.Fprintf(&b, "Commit `%s`. Changes are applied **before** this pull request is merged; it merges itself once every stack below has applied.\n\n", short(pr.HeadSHA))
	if len(rows) == 0 {
		b.WriteString("No contracts changed.\n")
		return b.String()
	}
	b.WriteString("| Stack | Business unit | Environment | Status | Risk | Approvals | Cost / month |\n|---|---|---|---|---|---|---|\n")
	for _, r := range rows {
		name := r.Stack
		if name == "" {
			name = "`" + r.File + "`"
		}
		status, riskCol, approvals, costCol := r.Action, "", "", ""
		if r.Error != "" {
			status = r.Action + ": " + strings.ReplaceAll(r.Error, "|", "\\|")
		}
		if r.Run != nil {
			status = fmt.Sprintf("[%s](%s)", strings.ReplaceAll(r.Run.Status, "_", " "), link(r.Run.ID))
			var rk risk.Result
			if json.Unmarshal(r.Run.Risk, &rk) == nil && rk.Level != "" {
				riskCol = rk.Level
			}
			if len(r.Run.RequiredApprovals) > 0 {
				signed := map[string]bool{}
				for _, a := range r.Run.Approvals {
					signed[a.Step] = true
				}
				var parts []string
				for _, st := range r.Run.RequiredApprovals {
					mark := "◻️"
					if signed[st] {
						mark = "☑️"
					}
					parts = append(parts, mark+" "+st)
				}
				approvals = strings.Join(parts, " ")
			}
			var c cost.Estimate
			if json.Unmarshal(r.Run.Cost, &c) == nil && r.Run.Cost != nil {
				costCol = fmt.Sprintf("%+.2f USD", c.MonthlyDelta)
			}
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", name, r.BU, r.Env, status, riskCol, approvals, costCol)
	}
	b.WriteString("\nApprove in Cloud Pravaha (or Slack). Comment `/plan` to plan again.\n")
	return b.String()
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func (s *Server) listPullRequests(w http.ResponseWriter, r *http.Request) {
	prs, err := s.store.ListPRs(r.Context(), limit(r, 20, 100))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, prs)
}

// replanPullRequest plans a pull request again (tenant admins), like a /plan comment.
func (s *Server) replanPullRequest(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		writeErr(w, 404, "not found")
		return
	}
	if err := s.planPR(r.Context(), n); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r.Context(), user(r).Actor(), "pr.replan", fmt.Sprintf("pr/%d", n), "", nil)
	pr, _ := s.store.GetPR(r.Context(), n)
	writeJSON(w, 200, pr)
}
