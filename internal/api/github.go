package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/githubapp"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// GitHub App integration: the tenant's own GitHub App authenticates contract
// fetches with short-lived installation tokens, and its webhooks reach the
// tenant plane through central (POST /webhooks/github/{tenant}), which relays
// them over mTLS. Only the tenant plane holds the webhook secret, so it alone
// verifies GitHub's signature.

const (
	githubAppSetting    = "github_app"
	githubKeySetting    = "github_app_private_key"
	githubSecretSetting = "github_webhook_secret"
	githubKeyAAD        = "github-app-private-key"
	githubSecretAAD     = "github-webhook-secret"
	// RelaySubject is the assertion subject central uses when it relays a webhook.
	RelaySubject = "system:webhook-relay"
)

type githubAppConfig struct {
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id,omitempty"` // found from the contracts repository when empty
	APIURL         string `json:"api_url,omitempty"`         // GitHub Enterprise Server: https://ghe.example.com/api/v3
	AppSlug        string `json:"app_slug,omitempty"`        // filled in by the connection test
}

type ghCache struct {
	mu  sync.Mutex
	sum [32]byte
	app *githubapp.App
}

func (s *Server) sealSetting(ctx context.Context, key, aad string, plain []byte, by string) error {
	sealed, err := s.sealer.Seal(plain, []byte(aad))
	if err != nil {
		return err
	}
	return s.store.PutSetting(ctx, key, map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)}, by)
}

func (s *Server) openSetting(ctx context.Context, key, aad string) ([]byte, bool) {
	var t map[string]string
	if ok, _ := s.store.Setting(ctx, key, &t); !ok {
		return nil, false
	}
	sealed, err := base64.StdEncoding.DecodeString(t["sealed"])
	if err != nil {
		return nil, false
	}
	pt, err := s.sealer.Open(sealed, []byte(aad))
	return pt, err == nil
}

// githubApp returns the configured app, reusing it (and its token cache)
// until the configuration or key changes.
func (s *Server) githubApp(ctx context.Context) (*githubapp.App, *githubAppConfig, error) {
	cfg, ok := s.githubAppConfig(ctx)
	if !ok {
		return nil, nil, errors.New("no GitHub App is configured")
	}
	pemKey := s.ghState().Key
	if len(pemKey) == 0 {
		return nil, nil, errors.New("the GitHub App private key is not set")
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s\x00%s", cfg.AppID, cfg.APIURL, pemKey)))
	s.gh.mu.Lock()
	defer s.gh.mu.Unlock()
	if s.gh.app != nil && s.gh.sum == sum {
		return s.gh.app, cfg, nil
	}
	key, err := githubapp.ParsePrivateKey(pemKey)
	if err != nil {
		return nil, nil, err
	}
	s.gh.app, s.gh.sum = &githubapp.App{ID: cfg.AppID, Key: key, API: cfg.APIURL}, sum
	return s.gh.app, cfg, nil
}

// githubInstallationToken mints a token for the installation covering repo.
func (s *Server) githubInstallationToken(ctx context.Context, repo string) (string, error) {
	app, cfg, err := s.githubApp(ctx)
	if err != nil {
		return "", err
	}
	id := cfg.InstallationID
	if id == 0 {
		inst, err := app.RepoInstallation(ctx, repo)
		if err != nil {
			return "", fmt.Errorf("the GitHub App is not installed on %s: %w", repo, err)
		}
		id = inst.ID
		cfg.InstallationID = id
		if err := s.ghSave(ctx, *cfg, nil, nil, "system:github"); err != nil {
			s.log.Warn("saving the GitHub App installation ID failed", "err", err)
		}
	}
	return app.Token(ctx, id)
}

func (s *Server) getGitHubIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	g := s.ghState()
	cfg, ok := &g.Cfg, g.OK
	resp := map[string]any{"configured": ok, "private_key_set": len(g.Key) > 0, "webhook_secret_set": len(g.Secret) > 0,
		"webhook_path": "/webhooks/github/" + s.cfg.Tenant, "source": g.Source}
	if g.Source == "env_file" {
		resp["env_file"] = s.cfg.EnvFile
	}
	if ok {
		resp["config"] = cfg
	}
	writeJSON(w, 200, resp)
}

func (s *Server) putGitHubIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		AppID          looseID `json:"app_id"`
		InstallationID looseID `json:"installation_id"`
		APIURL         string  `json:"api_url"`
		PrivateKey     string  `json:"private_key"`    // PEM; empty keeps the stored key
		WebhookSecret  string  `json:"webhook_secret"` // empty keeps the stored secret
	}
	if !decode(w, r, &b) {
		return
	}
	var probs []string
	appID, err := strconv.ParseInt(string(b.AppID), 10, 64)
	if err != nil || appID <= 0 {
		probs = append(probs, "app_id must be the numeric App ID from the app's settings page")
	}
	var instID int64
	if b.InstallationID != "" {
		if instID, err = strconv.ParseInt(string(b.InstallationID), 10, 64); err != nil || instID < 0 {
			probs = append(probs, "installation_id must be numeric (or empty to find it from the contracts repository)")
		}
	}
	if b.APIURL != "" {
		if u, err := url.Parse(b.APIURL); err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
			probs = append(probs, "api_url must be an https URL (GitHub Enterprise Server: https://HOST/api/v3; plain http only on loopback)")
		}
	}
	keySet := len(s.ghState().Key) > 0
	if b.PrivateKey != "" {
		if len(b.PrivateKey) > 16<<10 {
			probs = append(probs, "the private key is too large")
		} else if _, err := githubapp.ParsePrivateKey([]byte(b.PrivateKey)); err != nil {
			probs = append(probs, "private_key: "+err.Error()+" (use the .pem file GitHub generated)")
		}
	} else if !keySet {
		probs = append(probs, "private_key is required")
	}
	if b.WebhookSecret != "" && (len(b.WebhookSecret) < 16 || len(b.WebhookSecret) > 256) {
		probs = append(probs, "webhook_secret must be 16-256 characters")
	}
	if len(probs) > 0 {
		writeErr(w, 422, "invalid GitHub App settings", probs...)
		return
	}
	ctx, by := r.Context(), user(r).Subject
	prev, _ := s.githubAppConfig(ctx)
	cfg := githubAppConfig{AppID: appID, InstallationID: instID, APIURL: strings.TrimRight(b.APIURL, "/")}
	if prev != nil && prev.AppID == appID {
		cfg.AppSlug = prev.AppSlug
	}
	var key, secret []byte
	if b.PrivateKey != "" {
		key = []byte(strings.TrimSpace(b.PrivateKey) + "\n")
	}
	if b.WebhookSecret != "" {
		secret = []byte(b.WebhookSecret)
	}
	if err := s.ghSave(ctx, cfg, key, secret, by); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(ctx, user(r).Actor(), "integration.github.configure", "integration/github", "",
		map[string]any{"app_id": appID, "installation_id": instID, "api_url": cfg.APIURL, "private_key_changed": b.PrivateKey != "", "webhook_secret_changed": b.WebhookSecret != ""})
	s.getGitHubIntegration(w, r)
}

func (s *Server) deleteGitHubIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	if c, ok := s.contractsConfig(r.Context()); ok && c.Auth == "github_app" {
		writeErr(w, http.StatusConflict, "the contracts repository authenticates with this GitHub App; switch it to a token first")
		return
	}
	if err := s.ghClear(r.Context()); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "integration.github.remove", "integration/github", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

type check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | warn | fail
	Detail string `json:"detail"`
}

// testGitHubIntegration signs in as the app and checks what the platform needs.
func (s *Server) testGitHubIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var checks []check
	add := func(name, status, detail string) { checks = append(checks, check{name, status, detail}) }
	done := func() { writeJSON(w, 200, map[string]any{"checks": checks}) }

	app, cfg, err := s.githubApp(ctx)
	if err != nil {
		add("Credentials", "fail", err.Error())
		done()
		return
	}
	info, err := app.Info(ctx)
	if err != nil {
		add("Sign in as the app", "fail", err.Error()+" — check the App ID and that the private key belongs to this app")
		done()
		return
	}
	add("Sign in as the app", "ok", fmt.Sprintf("%s (app %d, owner %s)", info.Name, info.ID, info.Owner.Login))
	if cfg.AppSlug != info.Slug {
		cfg.AppSlug = info.Slug
		s.ghSave(ctx, *cfg, nil, nil, "system:github")
	}
	// What the installation actually granted is what counts: after an app's
	// permissions change, each installation's owner must accept the update.
	granted := info.Permissions
	if insts, err := app.Installations(ctx); err == nil {
		for _, i := range insts {
			if cfg.InstallationID == 0 || i.ID == cfg.InstallationID {
				granted = i.Permissions
				break
			}
		}
	}
	level := map[string]int{"": 0, "read": 1, "write": 2, "admin": 3}
	need := []struct{ perm, lvl, why string }{
		{"metadata", "read", "required"},
		{"contents", "write", "contracts (read) and self-service pull requests (write)"},
		{"pull_requests", "write", "pull-request plans: comments and merge after apply"},
		{"statuses", "write", "pull-request plans: the pravaha/apply status"},
	}
	var missing []string
	for _, n := range need {
		if level[granted[n.perm]] < level[n.lvl] {
			missing = append(missing, fmt.Sprintf("%s:%s (%s)", n.perm, n.lvl, n.why))
		}
	}
	var pending []string
	for p, l := range info.Permissions {
		if level[granted[p]] < level[l] {
			pending = append(pending, p+":"+l)
		}
	}
	switch {
	case len(missing) > 0:
		add("Permissions", "fail", "the installation lacks "+strings.Join(missing, "; "))
	default:
		add("Permissions", "ok", "metadata, contents (write), pull requests (write), statuses (write)")
	}
	if len(pending) > 0 {
		sort.Strings(pending)
		add("Pending permission update", "warn", "the app asks for "+strings.Join(pending, ", ")+" but the installation has not accepted them; the organisation owner can approve the request under Settings → GitHub Apps")
	}
	var extra []string
	for _, p := range []string{"repository_hooks", "administration", "secrets", "actions", "workflows", "organization_administration"} {
		if granted[p] != "" {
			extra = append(extra, p+":"+granted[p])
		}
	}
	if len(extra) > 0 {
		add("Least privilege", "warn", "the platform does not need "+strings.Join(extra, ", ")+"; remove them from the app")
	}
	events := map[string]bool{}
	for _, e := range info.Events {
		events[e] = true
	}
	var noEvents []string
	for _, e := range []string{"push", "pull_request", "issue_comment"} {
		if !events[e] {
			noEvents = append(noEvents, e)
		}
	}
	if len(noEvents) == 0 {
		add("Webhook events", "ok", strings.Join(info.Events, ", "))
	} else {
		add("Webhook events", "warn", "not subscribed to "+strings.Join(noEvents, ", ")+" (the app's Permissions & events page)")
	}
	if len(s.ghState().Secret) > 0 {
		add("Webhook secret", "ok", "set; deliveries are verified with X-Hub-Signature-256")
	} else {
		add("Webhook secret", "fail", "not set: webhook deliveries will be rejected")
	}
	cc, hasContracts := s.contractsConfig(ctx)
	if !hasContracts || cc.Provider != "github" {
		insts, err := app.Installations(ctx)
		if err != nil {
			add("Installations", "fail", err.Error())
		} else {
			var names []string
			for _, i := range insts {
				names = append(names, fmt.Sprintf("%s (%d)", i.Account.Login, i.ID))
			}
			add("Installations", map[bool]string{true: "ok", false: "warn"}[len(insts) > 0], "installed on: "+strings.Join(names, ", "))
		}
		done()
		return
	}
	inst, err := app.RepoInstallation(ctx, cc.Repo)
	if err != nil {
		add("Contracts repository", "fail", fmt.Sprintf("the app is not installed on %s: %v", cc.Repo, err))
		done()
		return
	}
	if cfg.InstallationID != 0 && cfg.InstallationID != inst.ID {
		add("Installation", "warn", fmt.Sprintf("configured installation %d, but %s is covered by installation %d", cfg.InstallationID, cc.Repo, inst.ID))
	}
	branch, private, err := app.RepoAccess(ctx, inst.ID, cc.Repo)
	if err != nil {
		add("Contracts repository", "fail", err.Error())
	} else {
		add("Contracts repository", "ok", fmt.Sprintf("%s readable with an installation token (installation %d, private %v, default branch %s)", cc.Repo, inst.ID, private, branch))
	}
	if cc.Auth != "github_app" {
		add("Contracts authentication", "warn", "the contracts repository still uses a token; switch it to the GitHub App")
	}
	done()
}

func (s *Server) listGitHubDeliveries(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	n := limit(r, 20, 100)
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	ds, err := s.store.ListDeliveries(r.Context(), n+1, before)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"items": ds}
	if len(ds) > n { // there is an older page
		resp["items"], resp["next_before"] = ds[:n], ds[n-1].ID
	}
	writeJSON(w, 200, resp)
}

// looseID accepts a number or a string (forms send strings); it is validated after decoding.
type looseID string

func (l *looseID) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case nil:
		*l = ""
	case string:
		*l = looseID(strings.TrimSpace(x))
	case float64:
		*l = looseID(strconv.FormatFloat(x, 'f', -1, 64))
	default:
		return errors.New("must be a number")
	}
	return nil
}

// authRelay accepts only central (mTLS client certificate) relaying a webhook
// with an assertion whose subject is the relay.
func (s *Server) authRelay(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		av, err := s.central.verifier(r.Context(), false)
		if err == nil {
			pr, verr := av.Verify(r.Header.Get(AssertionHeader), r.Method, r.URL.EscapedPath(), time.Now())
			if verr == nil && pr.Subject == RelaySubject {
				h(w, r)
				return
			}
		}
		writeErr(w, http.StatusUnauthorized, "unauthorized")
	})
}

// githubWebhook handles one delivery relayed by central.
func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 25<<20+1))
	if err != nil || len(body) > 25<<20 {
		writeErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	secret := s.ghState().Secret
	if len(secret) == 0 {
		writeErr(w, http.StatusServiceUnavailable, "no webhook secret is configured for this tenant")
		return
	}
	if !githubapp.VerifySignature(secret, body, r.Header.Get("X-Hub-Signature-256")) {
		s.log.Warn("GitHub webhook signature rejected", "delivery", r.Header.Get("X-GitHub-Delivery"))
		writeErr(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	var ev struct {
		Action string `json:"action"`
		Ref    string `json:"ref"`
		After  string `json:"after"`
		Hook   struct {
			AppID int64 `json:"app_id"`
		} `json:"hook"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Sender struct {
			Login string `json:"login"`
		} `json:"sender"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		writeErr(w, http.StatusBadRequest, "payload is not JSON")
		return
	}
	d := &store.WebhookDelivery{Provider: "github", DeliveryID: r.Header.Get("X-GitHub-Delivery"), Event: r.Header.Get("X-GitHub-Event"),
		Action: ev.Action, Repo: ev.Repository.FullName, Ref: ev.Ref, Sender: ev.Sender.Login}
	if d.DeliveryID == "" || d.Event == "" || len(d.DeliveryID) > 100 || len(d.Event) > 100 {
		writeErr(w, http.StatusBadRequest, "missing X-GitHub-Event or X-GitHub-Delivery")
		return
	}
	d.Outcome, d.Detail = s.handleGitHubEvent(r.Context(), d, ev.Hook.AppID, ev.Installation.ID, ev.PullRequest.Number, body)
	if err := s.store.RecordDelivery(r.Context(), d); errors.Is(err, store.ErrConflict) {
		writeJSON(w, 200, map[string]string{"outcome": "duplicate", "detail": "this delivery was already processed"})
		return
	} else if err != nil {
		s.log.Error("recording webhook delivery", "err", err)
	}
	writeJSON(w, 202, map[string]string{"outcome": d.Outcome, "detail": d.Detail})
}

func (s *Server) handleGitHubEvent(ctx context.Context, d *store.WebhookDelivery, hookAppID, installationID int64, pr int, body []byte) (string, string) {
	cfg, appOK := s.githubAppConfig(ctx)
	switch d.Event {
	case "ping":
		if appOK && hookAppID != 0 && hookAppID != cfg.AppID {
			return "rejected", fmt.Sprintf("ping from app %d, but this tenant is configured for app %d", hookAppID, cfg.AppID)
		}
		return "processed", "pong: the webhook reaches this tenant and its signature is valid"
	case "installation", "installation_repositories":
		if appOK && installationID != 0 && cfg.InstallationID == 0 && d.Action != "deleted" {
			cfg.InstallationID = installationID
			s.ghSave(ctx, *cfg, nil, nil, "system:github")
			return "processed", fmt.Sprintf("installation %d recorded", installationID)
		}
		return "processed", fmt.Sprintf("installation %d %s", installationID, d.Action)
	case "push":
		builds := s.releasePush(ctx, d.Repo, d.Ref)
		cc, ok := s.contractsConfig(ctx)
		if !ok || cc.Provider != "github" || !strings.EqualFold(cc.Repo, d.Repo) || d.Ref != "refs/heads/"+cc.Branch {
			if len(builds) > 0 {
				return "processed", "release build checked for " + strings.Join(builds, " and ")
			}
			if ok && strings.EqualFold(cc.Repo, d.Repo) {
				return "ignored", "push to " + d.Ref + ", contracts follow " + cc.Branch
			}
			return "ignored", "not the contracts, modules or policies repository"
		}
		go func() {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
			defer cancel()
			if _, err := s.syncContracts(sctx, false); err != nil {
				s.log.Warn("contracts sync after push failed", "err", err)
			}
		}()
		return "processed", "contracts sync started for " + cc.Branch
	case "pull_request":
		cc, ok := s.contractsConfig(ctx)
		if !ok || cc.Provider != "github" || !strings.EqualFold(cc.Repo, d.Repo) {
			return "ignored", "not the contracts repository"
		}
		var ev struct {
			PullRequest struct {
				Merged bool `json:"merged"`
				Base   struct {
					Ref string `json:"ref"`
				} `json:"base"`
			} `json:"pull_request"`
		}
		json.Unmarshal(body, &ev)
		if ev.PullRequest.Base.Ref != cc.Branch {
			return "ignored", "pull request targets " + ev.PullRequest.Base.Ref + ", contracts follow " + cc.Branch
		}
		switch d.Action {
		case "opened", "synchronize", "reopened", "ready_for_review":
			s.async(func(ctx context.Context) error { return s.planPR(ctx, pr) })
			return "processed", fmt.Sprintf("planning pull request #%d", pr)
		case "closed":
			merged := ev.PullRequest.Merged
			s.async(func(ctx context.Context) error { s.closePR(ctx, pr, merged); return nil })
			return "processed", fmt.Sprintf("pull request #%d closed (merged: %v)", pr, merged)
		}
		return "ignored", fmt.Sprintf("pull request #%d %s", pr, d.Action)
	case "issue_comment":
		var ev struct {
			Issue struct {
				Number      int             `json:"number"`
				PullRequest json.RawMessage `json:"pull_request"`
			} `json:"issue"`
			Comment struct {
				Body string `json:"body"`
			} `json:"comment"`
		}
		json.Unmarshal(body, &ev)
		if d.Action != "created" || len(ev.Issue.PullRequest) == 0 || strings.TrimSpace(ev.Comment.Body) != "/plan" {
			return "ignored", "not a /plan comment on a pull request"
		}
		if _, err := s.store.GetPR(ctx, ev.Issue.Number); err != nil {
			return "ignored", "pull request is not tracked (it does not target the contracts branch)"
		}
		n := ev.Issue.Number
		s.async(func(ctx context.Context) error { return s.planPR(ctx, n) })
		return "processed", fmt.Sprintf("planning pull request #%d again (requested by %s)", n, d.Sender)
	case "pull_request_review", "pull_request_review_comment", "pull_request_review_thread", "commit_comment":
		return "ignored", "reviews do not change plans; approvals happen in Cloud Pravaha"
	}
	return "ignored", "event not used"
}

// async runs background work started by a webhook, detached from the request.
func (s *Server) async(fn func(ctx context.Context) error) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if err := fn(ctx); err != nil {
			s.log.Warn("webhook follow-up failed", "err", err)
		}
	}()
}
