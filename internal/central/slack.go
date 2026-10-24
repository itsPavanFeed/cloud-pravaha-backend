package central

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/httpx"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
)

// Slack interactivity: the Approve / Reject buttons in Slack notifications
// post to POST /webhooks/slack/{tenant}. Central verifies Slack's signature with
// the tenant's Slack app signing secret, resolves the clicking user's email
// with the app's bot token, and acts on the tenant plane as that Cloud Pravaha
// user — the same approval call the console makes, with the same role checks,
// separation of duties and audit trail. Unknown people are refused.

const (
	slackSecretAAD = "slack-signing-secret"
	slackTokenAAD  = "slack-bot-token"
)

func slackAPI() string {
	if v := os.Getenv("PRAVAHA_SLACK_API_URL"); v != "" { // tests
		return strings.TrimRight(v, "/")
	}
	return "https://slack.com/api"
}

func (s *Server) getSlackApp(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	resp := map[string]any{"configured": false, "interactivity_url": s.webhookBase() + "/webhooks/slack/" + t.Slug}
	if a, err := s.store.SlackApp(r.Context(), t.ID); err == nil {
		resp["configured"], resp["updated_by"], resp["updated_at"] = true, a.UpdatedBy, a.UpdatedAt
	}
	httpx.WriteJSON(w, 200, resp)
}

func (s *Server) putSlackApp(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct {
		SigningSecret string `json:"signing_secret"`
		BotToken      string `json:"bot_token"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	if len(b.SigningSecret) < 16 || len(b.SigningSecret) > 128 || !strings.HasPrefix(b.BotToken, "xoxb-") || len(b.BotToken) > 256 {
		httpx.WriteErr(w, 422, "signing_secret (from the Slack app's Basic Information) and a bot token (xoxb-…, with users:read and users:read.email) are required")
		return
	}
	sealer, err := s.sealer()
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	sec, err1 := sealer.Seal([]byte(b.SigningSecret), []byte(slackSecretAAD+":"+t.ID))
	tok, err2 := sealer.Seal([]byte(b.BotToken), []byte(slackTokenAAD+":"+t.ID))
	if err := errors.Join(err1, err2); err != nil {
		s.storeErr(w, err, "")
		return
	}
	if err := s.store.PutSlackApp(r.Context(), t.ID, sec, tok, current(r).Email); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.slack_app", "tenant/"+t.Slug, t.Slug, map[string]bool{"set": true})
	s.getSlackApp(w, r)
}

func (s *Server) deleteSlackApp(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	if err := s.store.DeleteSlackApp(r.Context(), t.ID); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.slack_app_removed", "tenant/"+t.Slug, t.Slug, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sealer() (*secure.Sealer, error) {
	k, err := secure.ParseKey(s.cfg.MasterKey)
	if err != nil {
		return nil, err
	}
	return secure.NewSealer(k)
}

// verifySlack checks X-Slack-Signature: v0=HMAC-SHA256(secret, "v0:"+timestamp+":"+body),
// with the timestamp within five minutes (replay protection).
func verifySlack(secret, body []byte, ts, sig string, now time.Time) bool {
	t, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || now.Sub(time.Unix(t, 0)).Abs() > 5*time.Minute {
		return false
	}
	m := hmac.New(sha256.New, secret)
	fmt.Fprintf(m, "v0:%s:%s", ts, body)
	want := "v0=" + hex.EncodeToString(m.Sum(nil))
	return hmac.Equal([]byte(want), []byte(sig))
}

func (s *Server) slackInteraction(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.hookLimiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpx.WriteErr(w, http.StatusBadRequest, "bad request")
		return
	}
	ctx := r.Context()
	t, err := s.store.Tenant(ctx, r.PathValue("tenant"))
	if err != nil {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	app, err := s.store.SlackApp(ctx, t.ID)
	if err != nil {
		httpx.WriteErr(w, http.StatusNotFound, "Slack is not set up for this tenant")
		return
	}
	sealer, err := s.sealer()
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	secret, err1 := sealer.Open(app.SigningSecret, []byte(slackSecretAAD+":"+t.ID))
	token, err2 := sealer.Open(app.BotToken, []byte(slackTokenAAD+":"+t.ID))
	if errors.Join(err1, err2) != nil {
		s.storeErr(w, errors.Join(err1, err2), "")
		return
	}
	if !verifySlack(secret, body, r.Header.Get("X-Slack-Request-Timestamp"), r.Header.Get("X-Slack-Signature"), time.Now()) {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusUnauthorized, "invalid signature")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		httpx.WriteErr(w, http.StatusBadRequest, "bad request")
		return
	}
	var p struct {
		Type string `json:"type"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		ResponseURL string `json:"response_url"`
		Actions     []struct {
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
		} `json:"actions"`
	}
	if json.Unmarshal([]byte(form.Get("payload")), &p) != nil || p.Type != "block_actions" || len(p.Actions) == 0 {
		w.WriteHeader(http.StatusOK) // other interaction types are ignored
		return
	}
	msg := s.slackAct(ctx, t, string(token), p.User.ID, p.Actions[0].ActionID, p.Actions[0].Value)
	if p.ResponseURL != "" {
		go postSlackResponse(p.ResponseURL, msg)
	}
	w.WriteHeader(http.StatusOK)
}

// slackAct performs a button action as the Cloud Pravaha user behind the Slack
// account and returns the message to show in Slack.
func (s *Server) slackAct(ctx context.Context, t *Tenant, token, slackUser, actionID, value string) string {
	var v struct {
		Run  string `json:"run"`
		Step string `json:"step"`
	}
	if json.Unmarshal([]byte(value), &v) != nil || v.Run == "" {
		return ":x: Unknown action."
	}
	email, err := slackEmail(ctx, token, slackUser)
	if err != nil {
		s.log.Warn("slack user lookup failed", "err", err)
		return ":x: Could not look up your Slack profile's email (the app needs users:read.email)."
	}
	u, err := s.store.UserByEmail(ctx, email)
	if err != nil || u.DisabledAt != nil {
		s.audit(ctx, "slack:"+email, "slack.denied", "tenant/"+t.Slug, t.Slug, map[string]string{"reason": "no such Cloud Pravaha user"})
		return ":x: " + email + " is not a Cloud Pravaha user."
	}
	pr, err := s.store.Principal(ctx, u, t.Slug)
	if err != nil || pr == nil {
		return ":x: " + email + " has no access to this tenant."
	}
	var path string
	var body any
	switch {
	case strings.HasPrefix(actionID, "pravaha_approve_"):
		path, body = "/api/v1/runs/"+url.PathEscape(v.Run)+"/approve", map[string]string{"step": v.Step, "reason": "approved in Slack"}
	case actionID == "pravaha_reject":
		path, body = "/api/v1/runs/"+url.PathEscape(v.Run)+"/discard", map[string]string{"reason": "rejected in Slack"}
	default:
		return ":x: Unknown action."
	}
	code, out, err := s.callTenantAs(ctx, t, pr, http.MethodPost, path, body)
	s.audit(ctx, u.Email, "slack."+strings.TrimPrefix(actionID, "pravaha_"), "run/"+v.Run, t.Slug, map[string]any{"step": v.Step, "status": code})
	switch {
	case err != nil:
		return ":x: The tenant plane is unreachable: " + err.Error()
	case code >= 300:
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(out, &e)
		return fmt.Sprintf(":x: %s could not do that: %s", email, e.Error)
	case actionID == "pravaha_reject":
		return fmt.Sprintf(":no_entry: Rejected by %s. The plan was discarded; nothing is applied.", email)
	default:
		return fmt.Sprintf(":white_check_mark: %s approved as %s.", email, v.Step)
	}
}

// callTenantAs calls the tenant plane's API as a user, exactly like the wrapper.
func (s *Server) callTenantAs(ctx context.Context, t *Tenant, p *identity.Principal, method, path string, body any) (int, []byte, error) {
	b, _ := json.Marshal(body)
	assertion, err := identity.SignAssertion(s.issuer, p, method, path, time.Now())
	if err != nil {
		return 0, nil, err
	}
	rt, err := s.transport(t)
	if err != nil {
		return 0, nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, method, t.BackendURL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(assertionHeader, assertion)
	resp, err := (&http.Client{Transport: rt, Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, out, nil
}

func slackEmail(ctx context.Context, token, userID string) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, slackAPI()+"/users.info?user="+url.QueryEscape(userID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		User  struct {
			Deleted bool `json:"deleted"`
			Profile struct {
				Email string `json:"email"`
			} `json:"profile"`
		} `json:"user"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	if !out.OK || out.User.Deleted || out.User.Profile.Email == "" {
		return "", fmt.Errorf("users.info: %s", firstNonEmpty(out.Error, "no email"))
	}
	return strings.ToLower(out.User.Profile.Email), nil
}

func postSlackResponse(responseURL, text string) {
	u, err := url.Parse(responseURL)
	if err != nil || !(u.Scheme == "https" && (u.Host == "hooks.slack.com" || strings.HasSuffix(u.Host, ".slack.com")) ||
		u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost")) {
		return // only ever post back to Slack
	}
	b, _ := json.Marshal(map[string]any{"text": text, "replace_original": false, "response_type": "in_channel"})
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Post(responseURL, "application/json", bytes.NewReader(b))
	if err == nil {
		resp.Body.Close()
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
