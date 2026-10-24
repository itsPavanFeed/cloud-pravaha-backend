package central

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/httpx"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
)

// relaySubject must match api.RelaySubject on the tenant plane.
const relaySubject = "system:webhook-relay"

// githubWebhook is the public endpoint a tenant's GitHub App posts to:
// POST /webhooks/github/{tenant}. Central keeps no webhook secret; it relays the
// delivery unchanged to the tenant plane over mTLS with a relay assertion, and
// the tenant plane verifies GitHub's signature with its own secret.
func (s *Server) githubWebhook(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.hookLimiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	if r.Header.Get("X-GitHub-Event") == "" || r.Header.Get("X-Hub-Signature-256") == "" {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusBadRequest, "not a signed GitHub webhook delivery")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 25<<20+1)) // GitHub caps payloads at 25 MB
	if err != nil || len(body) > 25<<20 {
		httpx.WriteErr(w, http.StatusRequestEntityTooLarge, "payload too large")
		return
	}
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		s.hookLimiter.Fail(ip)
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	const path = "/api/v1/webhooks/github"
	assertion, err := identity.SignAssertion(s.issuer, &identity.Principal{Subject: relaySubject, Tenant: t.Slug}, http.MethodPost, path, time.Now())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	rt, err := s.transport(t)
	if err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, "tenant is misconfigured")
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, t.BackendURL+path, bytes.NewReader(body))
	for _, h := range []string{"Content-Type", "User-Agent", "X-GitHub-Event", "X-GitHub-Delivery", "X-Hub-Signature-256",
		"X-GitHub-Hook-ID", "X-GitHub-Hook-Installation-Target-ID", "X-GitHub-Hook-Installation-Target-Type"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	req.Header.Set(assertionHeader, assertion)
	resp, err := (&http.Client{Transport: rt, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		s.log.Warn("webhook relay failed", "tenant", t.Slug, "err", err)
		httpx.WriteErr(w, http.StatusBadGateway, "tenant is unreachable")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		s.hookLimiter.Fail(ip)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, io.LimitReader(resp.Body, 64<<10))
}
