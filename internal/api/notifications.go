package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/envfile"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// Notifications: every platform event of interest is stored for the in-app
// notification centre (filtered by business unit like everything else) and
// sent to the tenant's Slack channel when an incoming webhook is configured.
// Approval requests carry Approve / Reject buttons when Slack interactivity is
// set up on the central plane, which acts on them as the clicking person.

type slackSettings struct {
	WebhookURL  string `json:"webhook_url"`
	Interactive bool   `json:"interactive"` // central has the Slack app's signing secret: show buttons
}

const (
	slackSetting    = "slack"
	slackAAD        = "slack-webhook"
	envSlackURL     = "PRAVAHA_SLACK_WEBHOOK_URL"
	envSlackButtons = "PRAVAHA_SLACK_INTERACTIVE"
)

// notifyEvent records a notification and forwards it to Slack. It never fails the caller.
func (s *Server) notifyEvent(ctx context.Context, n store.Notification) {
	saved, err := s.store.AddNotification(context.WithoutCancel(ctx), &n)
	if err != nil {
		s.log.Warn("storing a notification failed", "kind", n.Kind, "err", err)
		return
	}
	if sl := s.slack(); sl.WebhookURL != "" {
		go s.sendSlack(sl, saved)
	}
}

func (s *Server) notifyRun(ctx context.Context, run *store.Run, kind, severity, title, body string, steps []string) {
	id := run.ID
	s.notifyEvent(ctx, store.Notification{Kind: kind, Severity: severity, Title: title, Body: body, Link: "runs/" + run.ID,
		BU: run.BU, Entity: run.Entity, RunID: &id, Steps: steps})
}

func (s *Server) slack() slackSettings {
	if p := s.slackSnap.Load(); p != nil {
		return *p
	}
	return slackSettings{}
}

func (s *Server) loadSlack(ctx context.Context) {
	var sl slackSettings
	if s.cfg.EnvFile != "" {
		if m, err := envfile.Read(s.cfg.EnvFile); err == nil {
			sl.WebhookURL, sl.Interactive = m[envSlackURL], m[envSlackButtons] == "1"
		}
	} else if b, ok := s.openSetting(ctx, slackSetting, slackAAD); ok {
		json.Unmarshal(b, &sl)
	}
	s.slackSnap.Store(&sl)
}

func validSlackURL(u string) bool {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return false
	}
	if p.Scheme == "http" && (p.Hostname() == "127.0.0.1" || p.Hostname() == "localhost") {
		return true // development and tests
	}
	return p.Scheme == "https" && (p.Host == "hooks.slack.com" || strings.HasSuffix(p.Host, ".slack.com") || strings.HasSuffix(p.Host, ".slack-gov.com"))
}

var slackIcon = map[string]string{"action": ":large_orange_circle:", "success": ":white_check_mark:", "error": ":x:", "warning": ":warning:", "info": ":information_source:"}

func (s *Server) consoleURL(link string) string {
	return strings.TrimRight(s.cfg.CentralURL, "/") + "/#/t/" + s.cfg.Tenant + "/" + link
}

// slackMessage builds the Block Kit message for a notification.
func (s *Server) slackMessage(sl slackSettings, n *store.Notification) map[string]any {
	scope := s.cfg.Tenant
	if n.BU != "" {
		scope += " · " + n.Entity + "/" + n.BU
	}
	text := fmt.Sprintf("%s *%s*", slackIcon[n.Severity], n.Title)
	if n.Body != "" {
		text += "\n" + n.Body
	}
	blocks := []any{
		map[string]any{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": text}},
		map[string]any{"type": "context", "elements": []any{map[string]string{"type": "mrkdwn", "text": scope + " · Cloud Pravaha"}}},
	}
	actions := []any{}
	if n.Link != "" {
		actions = append(actions, map[string]any{"type": "button", "text": map[string]string{"type": "plain_text", "text": "Open in Cloud Pravaha"}, "url": s.consoleURL(n.Link)})
	}
	if sl.Interactive && n.Severity == "action" && n.RunID != nil {
		for _, step := range n.Steps {
			v, _ := json.Marshal(map[string]string{"run": *n.RunID, "step": step})
			actions = append(actions, map[string]any{"type": "button", "style": "primary", "action_id": "pravaha_approve_" + step,
				"text": map[string]string{"type": "plain_text", "text": "Approve as " + step}, "value": string(v)})
		}
		v, _ := json.Marshal(map[string]string{"run": *n.RunID})
		actions = append(actions, map[string]any{"type": "button", "style": "danger", "action_id": "pravaha_reject",
			"text": map[string]string{"type": "plain_text", "text": "Reject"}, "value": string(v),
			"confirm": map[string]any{"title": map[string]string{"type": "plain_text", "text": "Reject this plan?"},
				"text":    map[string]string{"type": "plain_text", "text": "The plan is discarded and nothing is applied."},
				"confirm": map[string]string{"type": "plain_text", "text": "Reject"}, "deny": map[string]string{"type": "plain_text", "text": "Cancel"}}})
	}
	if len(actions) > 0 {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": actions})
	}
	return map[string]any{"text": n.Title, "blocks": blocks}
}

func (s *Server) sendSlack(sl slackSettings, n *store.Notification) error {
	b, _ := json.Marshal(s.slackMessage(sl, n))
	hc := &http.Client{Timeout: 10 * time.Second}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt*2) * time.Second)
		}
		resp, err := hc.Post(sl.WebhookURL, "application/json", bytes.NewReader(b))
		if err != nil {
			lastErr = err
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("slack returned %s", resp.Status)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			break
		}
	}
	s.log.Warn("sending a Slack notification failed", "kind", n.Kind, "err", lastErr)
	return lastErr
}

// ---- API ----

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request) {
	n := limit(r, 20, 100)
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	items, err := s.store.ListNotifications(r.Context(), visible(r), before, n+1)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"items": items}
	if len(items) > n {
		resp["items"], resp["next_before"] = items[:n], items[n-1].ID
	}
	writeJSON(w, 200, resp)
}

func (s *Server) unreadNotifications(w http.ResponseWriter, r *http.Request) {
	n, last, err := s.store.UnreadNotifications(r.Context(), user(r).Subject, visible(r))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, map[string]any{"unread": n, "latest_id": last})
}

func (s *Server) readNotifications(w http.ResponseWriter, r *http.Request) {
	var b struct {
		UpTo int64 `json:"up_to"`
	}
	if !decode(w, r, &b) {
		return
	}
	if err := s.store.MarkNotificationsRead(r.Context(), user(r).Subject, b.UpTo); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getSlackIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	sl := s.slack()
	host := ""
	if u, err := url.Parse(sl.WebhookURL); err == nil {
		host = u.Host
	}
	src := "database"
	if s.cfg.EnvFile != "" {
		src = "env_file"
	}
	writeJSON(w, 200, map[string]any{"configured": sl.WebhookURL != "", "webhook_host": host, "interactive": sl.Interactive,
		"source": src, "interactivity_path": "/webhooks/slack/" + s.cfg.Tenant})
}

func (s *Server) putSlackIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var b struct {
		WebhookURL  string `json:"webhook_url"` // empty keeps the stored URL
		Interactive bool   `json:"interactive"`
	}
	if !decode(w, r, &b) {
		return
	}
	cur := s.slack()
	if b.WebhookURL == "" {
		b.WebhookURL = cur.WebhookURL
	}
	if b.WebhookURL == "" || !validSlackURL(b.WebhookURL) {
		writeErr(w, 422, "webhook_url must be a Slack incoming webhook URL (https://hooks.slack.com/services/...)")
		return
	}
	sl := slackSettings{WebhookURL: b.WebhookURL, Interactive: b.Interactive}
	var err error
	if s.cfg.EnvFile != "" {
		v := ""
		if sl.Interactive {
			v = "1"
		}
		err = envfile.Update(s.cfg.EnvFile, map[string]string{envSlackURL: sl.WebhookURL, envSlackButtons: v})
	} else {
		raw, _ := json.Marshal(sl)
		err = s.sealSetting(r.Context(), slackSetting, slackAAD, raw, user(r).Subject)
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.loadSlack(r.Context())
	s.audit(r.Context(), user(r).Actor(), "integration.slack.configure", "integration/slack", "", map[string]any{"interactive": sl.Interactive, "url_changed": b.WebhookURL != cur.WebhookURL})
	s.getSlackIntegration(w, r)
}

func (s *Server) deleteSlackIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	var err error
	if s.cfg.EnvFile != "" {
		err = envfile.Update(s.cfg.EnvFile, map[string]string{envSlackURL: "", envSlackButtons: ""})
	} else {
		err = s.store.DeleteSetting(r.Context(), slackSetting)
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.loadSlack(r.Context())
	s.audit(r.Context(), user(r).Actor(), "integration.slack.remove", "integration/slack", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) testSlackIntegration(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	sl := s.slack()
	if sl.WebhookURL == "" {
		writeErr(w, http.StatusConflict, "no Slack webhook is configured")
		return
	}
	n := &store.Notification{Kind: "test", Severity: "info", Title: "Cloud Pravaha is connected to this channel",
		Body: "Sent by " + user(r).Subject + " from Integrations → Slack.", Link: "integrations/slack"}
	if err := s.sendSlack(sl, n); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
