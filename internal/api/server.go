// Package api is a tenant plane's HTTP surface: the REST API the central plane
// forwards user requests to, the runner (agent) API, the OpenTofu HTTP state
// backend and the OIDC issuer clouds trust for this tenant's runs.
//
// User requests are accepted only from the central plane: the TLS connection
// must present central's client certificate (mTLS), and each request must carry
// a short-lived assertion signed by central, bound to the method and path and
// naming this tenant. This plane never sees users' API tokens.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/assistant"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/blob"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/bundlecache"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/certs"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/config"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/httpx"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/orchestrator"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// AssertionHeader carries central's signed assertion on forwarded requests.
const AssertionHeader = "X-Pravaha-Assertion"

type Server struct {
	cfg     *config.Server
	store   *store.Store
	sealer  *secure.Sealer
	issuer  *oidc.Issuer
	log     *slog.Logger
	limiter *httpx.Limiter
	central *centralKeys
	objects *blob.S3 // tenant bucket for state and plans; nil = keep them in PostgreSQL
	engine  orchestrator.Engine
	wakeMu  sync.Mutex
	wake    chan struct{} // closed to nudge long-polling runners when work is queued

	assistant      *assistant.Assistant            // nil = disabled
	assistantDocs  atomic.Pointer[[]assistant.Doc] // catalog, guide and runbooks
	assistantExtra []assistant.Doc                 // runbooks from PRAVAHA_ASSISTANT_DOCS_DIR
	askLimiter     *httpx.Limiter
	gh             ghCache                           // GitHub App with its token cache
	ghSnap         atomic.Pointer[ghSettings]        // GitHub App settings, reloaded on change
	dirSnap        atomic.Pointer[map[string]string] // business unit → entity, learned from central
	slackSnap      atomic.Pointer[slackSettings]     // Slack incoming webhook, reloaded on change
	platSnap       atomic.Pointer[platform]          // catalog, tenant defaults and deployed module release
	bundles        *bundlecache.Cache                // release bundles: memory, then disk, then the database or bucket
}

func New(cfg *config.Server, st *store.Store, cat *catalog.Catalog, sealer *secure.Sealer, iss *oidc.Issuer, log *slog.Logger) (*Server, error) {
	ck, err := newCentralKeys(cfg)
	if err != nil {
		return nil, err
	}
	srv := &Server{cfg: cfg, store: st, sealer: sealer, issuer: iss, log: log, central: ck,
		limiter: httpx.NewLimiter(10, time.Minute, 5*time.Minute), wake: make(chan struct{}), engine: orchestrator.Builtin{},
		askLimiter: httpx.NewLimiter(60, time.Hour, 15*time.Minute)}
	bundled, err := bundledPlatform(cat, cfg.CatalogDir, cfg.Tenant)
	if err != nil {
		return nil, err
	}
	srv.platSnap.Store(bundled)
	if srv.bundles, err = bundlecache.New(srv.loadBundle, cfg.BundleCacheDir, cfg.BundleCacheMem, cfg.BundleCacheDisk); err != nil {
		log.Warn("the bundle disk cache is unavailable; caching in memory only", "dir", cfg.BundleCacheDir, "err", err)
		srv.bundles, _ = bundlecache.New(srv.loadBundle, "", cfg.BundleCacheMem, 0)
	}
	srv.loadActiveRelease(context.Background())
	if err := srv.enableAssistant(); err != nil {
		return nil, err
	}
	srv.loadDirectory(context.Background())
	srv.loadSlack(context.Background())
	if err := srv.ghReload(context.Background()); err != nil {
		return nil, fmt.Errorf("loading GitHub App settings: %w", err)
	}
	if cfg.BucketURL != "" {
		bc, err := blob.ParseURL(cfg.BucketURL, cfg.BucketAccessKey, cfg.BucketSecretKey)
		if err != nil {
			return nil, fmt.Errorf("PRAVAHA_BUCKET_URL: %w", err)
		}
		srv.objects = blob.New(bc, nil)
		if cfg.BucketCreate {
			if err := srv.objects.EnsureBucket(context.Background()); err != nil {
				return nil, fmt.Errorf("creating bucket: %w", err)
			}
		}
		log.Info("state and plans are stored in the tenant bucket", "bucket", bc.Bucket, "endpoint", bc.Endpoint)
	}
	return srv, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{"status": "ok", "tenant": s.cfg.Tenant})
	})
	mux.HandleFunc("GET /.well-known/openid-configuration", s.raw(s.issuer.Discovery))
	mux.HandleFunc("GET /.well-known/jwks.json", s.raw(s.issuer.JWKS))

	// Users, via the central plane. Fine-grained checks happen in each handler,
	// because they depend on the entity of the resource being touched.
	u := func(h http.HandlerFunc) http.Handler { return s.authUser(h) }
	mux.Handle("GET /api/v1/me", u(s.me))
	mux.Handle("GET /api/v1/catalog", u(s.getCatalog))
	mux.Handle("GET /api/v1/connections", u(s.listConnections))
	mux.Handle("POST /api/v1/connections", u(s.createConnection))
	mux.Handle("GET /api/v1/connections/{id}", u(s.getConnection))
	mux.Handle("PUT /api/v1/connections/{id}", u(s.updateConnection))
	mux.Handle("DELETE /api/v1/connections/{id}", u(s.deleteConnection))
	mux.Handle("GET /api/v1/environments", u(s.listEnvironments))
	mux.Handle("POST /api/v1/environments", u(s.createEnvironment))
	mux.Handle("GET /api/v1/environments/{id}", u(s.getEnvironment))
	mux.Handle("PUT /api/v1/environments/{id}", u(s.updateEnvironment))
	mux.Handle("DELETE /api/v1/environments/{id}", u(s.deleteEnvironment))
	mux.Handle("GET /api/v1/stacks", u(s.listStacks))
	mux.Handle("POST /api/v1/stacks", u(s.createStack))
	mux.Handle("POST /api/v1/stacks/preview", u(s.previewStack))
	mux.Handle("POST /api/v1/stacks/propose", u(s.proposeStack))
	mux.Handle("GET /api/v1/stacks/{id}", u(s.getStack))
	mux.Handle("PUT /api/v1/stacks/{id}", u(s.updateStack))
	mux.Handle("GET /api/v1/stacks/{id}/runs", u(s.listStackRuns))
	mux.Handle("POST /api/v1/stacks/{id}/runs", u(s.createRun))
	mux.Handle("PUT /api/v1/stacks/{id}/drift", u(s.setDrift))
	mux.Handle("GET /api/v1/stacks/{id}/state-versions", u(s.listStateVersions))
	mux.Handle("GET /api/v1/runs", u(s.listRuns))
	mux.Handle("GET /api/v1/runs/{id}", u(s.getRun))
	mux.Handle("GET /api/v1/runs/{id}/logs", u(s.getRunLogs))
	mux.Handle("POST /api/v1/runs/{id}/approve", u(s.approveRun))
	mux.Handle("POST /api/v1/runs/{id}/override", u(s.overrideRun))
	mux.Handle("POST /api/v1/runs/{id}/discard", u(s.discardRun))
	mux.Handle("GET /api/v1/audit", u(s.listAudit))
	mux.Handle("GET /api/v1/audit/verify", u(s.verifyAudit))
	mux.Handle("GET /api/v1/contracts", u(s.getContracts))
	mux.Handle("PUT /api/v1/contracts", u(s.putContracts))
	mux.Handle("PUT /api/v1/contracts/token", u(s.putContractsToken))
	mux.Handle("POST /api/v1/contracts/sync", u(s.syncContractsNow))
	mux.Handle("GET /api/v1/policies", u(s.listPolicies))
	mux.Handle("POST /api/v1/policies", u(s.createPolicy))
	mux.Handle("PUT /api/v1/policies/{id}", u(s.updatePolicy))
	mux.Handle("DELETE /api/v1/policies/{id}", u(s.deletePolicy))
	mux.Handle("POST /api/v1/policies/test", u(s.testPolicy))
	mux.Handle("GET /api/v1/settings/risk", u(s.getRiskSettings))
	mux.Handle("PUT /api/v1/settings/risk", u(s.putRiskSettings))
	mux.Handle("GET /api/v1/assistant", u(s.assistantInfo))
	mux.Handle("POST /api/v1/assistant/ask", u(s.askAssistant))
	mux.Handle("GET /api/v1/integrations/github", u(s.getGitHubIntegration))
	mux.Handle("PUT /api/v1/integrations/github", u(s.putGitHubIntegration))
	mux.Handle("DELETE /api/v1/integrations/github", u(s.deleteGitHubIntegration))
	mux.Handle("POST /api/v1/integrations/github/test", u(s.testGitHubIntegration))
	mux.Handle("GET /api/v1/integrations/github/deliveries", u(s.listGitHubDeliveries))
	mux.Handle("POST /api/v1/webhooks/github", s.authRelay(s.githubWebhook))
	mux.Handle("GET /api/v1/pull-requests", u(s.listPullRequests))
	mux.Handle("GET /api/v1/notifications", u(s.listNotifications))
	mux.Handle("GET /api/v1/notifications/unread", u(s.unreadNotifications))
	mux.Handle("POST /api/v1/notifications/read", u(s.readNotifications))
	mux.Handle("GET /api/v1/integrations/slack", u(s.getSlackIntegration))
	mux.Handle("PUT /api/v1/integrations/slack", u(s.putSlackIntegration))
	mux.Handle("DELETE /api/v1/integrations/slack", u(s.deleteSlackIntegration))
	mux.Handle("POST /api/v1/integrations/slack/test", u(s.testSlackIntegration))
	mux.Handle("GET /api/v1/releases/cache", u(s.bundleCacheStats))
	mux.Handle("GET /api/v1/releases/{kind}", u(s.listReleases))
	mux.Handle("GET /api/v1/releases/{kind}/source", u(s.getReleaseSource))
	mux.Handle("PUT /api/v1/releases/{kind}/source", u(s.putReleaseSource))
	mux.Handle("PUT /api/v1/releases/{kind}/source/token", u(s.putReleaseToken))
	mux.Handle("POST /api/v1/releases/{kind}/builds", u(s.buildReleaseNow))
	mux.Handle("GET /api/v1/releases/{kind}/{id}", u(s.getRelease))
	mux.Handle("GET /api/v1/releases/{kind}/files", u(s.getReleaseFile))
	mux.Handle("POST /api/v1/releases/{kind}/changes", u(s.proposeReleaseChange))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/request", u(s.requestActivation))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/approve", u(s.approveRelease))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/reject", u(s.rejectRelease))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/merge", u(s.retryMerge))
	mux.Handle("POST /api/v1/releases/{kind}/{id}/override", u(s.overrideRelease))
	mux.Handle("GET /api/v1/integrations/secret-store", u(s.getSecretStore))
	mux.Handle("PUT /api/v1/integrations/secret-store", u(s.putSecretStore))
	mux.Handle("DELETE /api/v1/integrations/secret-store", u(s.deleteSecretStore))
	mux.Handle("POST /api/v1/integrations/secret-store/test", u(s.testSecretStore))
	mux.Handle("POST /api/v1/pull-requests/{n}/plan", u(s.replanPullRequest))
	mux.Handle("GET /api/v1/runners", u(s.listRunners))
	mux.Handle("POST /api/v1/runners", u(s.createRunner))
	mux.Handle("DELETE /api/v1/runners/{id}", u(s.revokeRunner))

	// Runners (pvh_r_ tokens) claim work; run tokens (pvh_t_) act on one run.
	mux.Handle("POST /api/v1/agent/claim", s.authRunner(s.claim))
	mux.Handle("POST /api/v1/agent/runs/{id}/logs", s.authRun(s.agentLogs))
	mux.Handle("POST /api/v1/agent/runs/{id}/plan", s.authRun(s.agentPlan))
	mux.Handle("GET /api/v1/agent/runs/{id}/plan", s.authRun(s.agentGetPlan))
	mux.Handle("POST /api/v1/agent/runs/{id}/finish", s.authRun(s.agentFinish))
	mux.Handle("GET /api/v1/agent/runs/{id}/bundles/{sha}", s.authRun(s.agentBundle))

	// OpenTofu HTTP state backend, authenticated with the run token.
	mux.HandleFunc("/state/v1/{stack}", s.state)

	return httpx.SecurityHeaders(true, mux)
}

// Run serves HTTPS. Client certificates are optional at the TLS layer (runners
// do not have one) and required by authUser for user requests.
func (s *Server) Run(ctx context.Context) error {
	// Certificates and the client CA reload from disk when rotated.
	kp, err := certs.NewKeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("TLS certificate: %w", err)
	}
	pool, err := certs.NewPool(s.cfg.CentralClientCA)
	if err != nil {
		return fmt.Errorf("PRAVAHA_CENTRAL_CLIENT_CA: %w", err)
	}
	tlsCfg := certs.ServerConfig(kp, pool)
	if s.cfg.TemporalAddress != "" {
		t, err := orchestrator.NewTemporal(orchestrator.TemporalConfig{
			Address: s.cfg.TemporalAddress, Namespace: s.cfg.TemporalNamespace,
			TaskQueue: "pravaha-" + s.cfg.Tenant, Timeouts: orchestrator.DefaultTimeouts,
		}, &orchestrator.Activities{Store: orchStore{s}, OnQueue: func(ctx context.Context, ids []string) {
			for _, id := range ids {
				s.engine.RunCreated(ctx, id)
			}
			s.notify()
		}}, func(msg string, args ...any) { s.log.Warn(msg, args...) })
		if err != nil {
			return fmt.Errorf("connecting to Temporal at %s: %w", s.cfg.TemporalAddress, err)
		}
		defer t.Close()
		s.engine = t
		s.log.Info("run lifecycles are orchestrated by Temporal", "address", s.cfg.TemporalAddress, "task_queue", "pravaha-"+s.cfg.Tenant)
	} else {
		go s.driftScheduler(ctx)
	}
	go s.reaper(ctx)
	go s.contractsSyncer(ctx)
	go s.ghWatch(ctx)
	go s.prReconciler(ctx)
	go s.releaseSyncer(ctx)
	s.log.Info("tenant plane serving HTTPS", "tenant", s.cfg.Tenant, "listen", s.cfg.Listen, "central", s.cfg.CentralURL)
	return httpx.Serve(ctx, s.log, s.cfg.Listen, s.Handler(), tlsCfg, "", "")
}

func (s *Server) reaper(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.engine.Name() == "builtin" { // Temporal owns run timers otherwise
				ids, err := s.store.Reap(ctx, 15*time.Minute, 24*time.Hour)
				if err != nil {
					s.log.Error("reaper", "err", err)
					continue
				}
				for _, id := range ids {
					s.audit(ctx, "system", "run.reaped", "run/"+id, "", nil)
				}
			}
			s.store.ReleaseRunLocks(ctx)
			s.cleanupPlans(ctx)
		}
	}
}

// orchStore adapts the tenant plane for workflow activities.
type orchStore struct{ s *Server }

func (o orchStore) Expire(ctx context.Context, runID string, from []string, to, reason string) (bool, error) {
	moved, err := o.s.store.Expire(ctx, runID, from, to, reason)
	if moved {
		o.s.audit(ctx, "system:temporal", "run.expired", "run/"+runID, "", map[string]string{"status": to, "reason": reason})
	}
	return moved, err
}

func (o orchStore) QueueDueDrift(ctx context.Context) ([]string, error) {
	return o.s.queueDueDrift(ctx), nil
}

// runCreated wakes runners and starts the run's lifecycle in the engine.
func (s *Server) runCreated(ctx context.Context, runID string) {
	s.engine.RunCreated(ctx, runID)
	s.notify()
}

func (s *Server) notify() {
	s.wakeMu.Lock()
	close(s.wake)
	s.wake = make(chan struct{})
	s.wakeMu.Unlock()
}

func (s *Server) wakeCh() <-chan struct{} {
	s.wakeMu.Lock()
	defer s.wakeMu.Unlock()
	return s.wake
}

// ---- central signing keys ----

// centralKeys verifies assertions with central's JWKS, fetched lazily and
// refreshed (at most once a minute) when an unknown key ID appears, so
// central can rotate keys without restarting tenant planes.
type centralKeys struct {
	cfg     *config.Server
	hc      *http.Client
	mu      sync.Mutex
	av      *identity.AssertionVerifier
	fetched time.Time
}

func newCentralKeys(cfg *config.Server) (*centralKeys, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CentralCAFile != "" {
		pem, err := os.ReadFile(cfg.CentralCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("PRAVAHA_CENTRAL_CA_FILE contains no certificates")
		}
		tc.RootCAs = pool
	}
	ck := &centralKeys{cfg: cfg, hc: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}}
	if cfg.CentralJWKSFile != "" {
		b, err := os.ReadFile(cfg.CentralJWKSFile)
		if err != nil {
			return nil, err
		}
		if err := ck.load(b); err != nil {
			return nil, err
		}
	}
	return ck, nil
}

func (c *centralKeys) load(jwks []byte) error {
	v, err := oidc.NewVerifier(c.cfg.CentralIssuer, jwks)
	if err != nil {
		return err
	}
	c.av = identity.NewAssertionVerifier(c.cfg.Tenant, v)
	return nil
}

func (c *centralKeys) verifier(ctx context.Context, refresh bool) (*identity.AssertionVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.av != nil && (!refresh || c.cfg.CentralJWKSFile != "" || time.Since(c.fetched) < time.Minute) {
		return c.av, nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.CentralURL+"/.well-known/jwks.json", nil)
	resp, err := c.hc.Do(req)
	if err != nil {
		if c.av != nil {
			return c.av, nil
		}
		return nil, fmt.Errorf("fetching central JWKS: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	c.fetched = time.Now()
	if resp.StatusCode != http.StatusOK {
		return c.av, fmt.Errorf("central JWKS: %s", resp.Status)
	}
	// Keep the replay cache across refreshes.
	v, err := oidc.NewVerifier(c.cfg.CentralIssuer, b)
	if err != nil {
		return c.av, err
	}
	if c.av == nil {
		c.av = identity.NewAssertionVerifier(c.cfg.Tenant, v)
	} else {
		c.av.SetVerifier(v)
	}
	return c.av, nil
}

// ---- principals & auth ----

type principal struct {
	Kind   string // user | runner | run
	User   *identity.Principal
	Runner *store.Runner
	Run    *store.Run
}

func (p *principal) Subject() string {
	switch p.Kind {
	case "user":
		return p.User.Actor()
	case "runner":
		return "runner:" + p.Runner.Name
	}
	return "run:" + p.Run.ID
}

type ctxKey struct{}

func who(r *http.Request) *principal { return r.Context().Value(ctxKey{}).(*principal) }

func user(r *http.Request) *identity.Principal { return who(r).User }

// authUser accepts a request only over central's mTLS client certificate with
// a valid assertion for this tenant and this exact request.
func (s *Server) authUser(h http.HandlerFunc) http.Handler {
	return s.withLimiter(func(w http.ResponseWriter, r *http.Request) bool {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			return false
		}
		tok := r.Header.Get(AssertionHeader)
		if tok == "" {
			return false
		}
		av, err := s.central.verifier(r.Context(), false)
		if err != nil {
			s.log.Error("central keys unavailable", "err", err)
			writeErr(w, http.StatusServiceUnavailable, "cannot verify requests: central plane keys unavailable")
			return true
		}
		p, err := av.Verify(tok, r.Method, r.URL.EscapedPath(), time.Now())
		if err != nil && err.Error() == "unknown signing key" {
			if av, err2 := s.central.verifier(r.Context(), true); err2 == nil {
				p, err = av.Verify(tok, r.Method, r.URL.EscapedPath(), time.Now())
			}
		}
		if err != nil {
			s.log.Warn("assertion rejected", "err", err, "ip", clientIP(r))
			return false
		}
		s.noteDirectory(r.Context(), p.BUEntity)
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{Kind: "user", User: p})))
		return true
	})
}

func (s *Server) authRunner(h http.HandlerFunc) http.Handler {
	return s.withLimiter(func(w http.ResponseWriter, r *http.Request) bool {
		tok := httpx.Bearer(r)
		if len(tok) < 7 || tok[:6] != "pvh_r_" {
			return false
		}
		rn, err := s.store.RunnerByHash(r.Context(), secure.HashToken(tok))
		if err != nil {
			return false
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{Kind: "runner", Runner: rn})))
		return true
	})
}

// authRun accepts a run token as Bearer or as the Basic-auth password (the
// form OpenTofu's HTTP backend sends). The token only works for its own run.
func (s *Server) authRun(h http.HandlerFunc) http.Handler {
	return s.withLimiter(func(w http.ResponseWriter, r *http.Request) bool {
		run, ok := s.runFromRequest(r)
		if !ok {
			return false
		}
		if id := r.PathValue("id"); id != "" && id != run.ID {
			return false
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &principal{Kind: "run", Run: run})))
		return true
	})
}

func (s *Server) runFromRequest(r *http.Request) (*store.Run, bool) {
	tok := httpx.Bearer(r)
	if tok == "" {
		_, tok, _ = r.BasicAuth()
	}
	if len(tok) < 7 || tok[:6] != "pvh_t_" {
		return nil, false
	}
	run, err := s.store.RunByToken(r.Context(), secure.HashToken(tok))
	return run, err == nil
}

// withLimiter rejects unauthenticated requests and rate-limits failures per client IP.
func (s *Server) withLimiter(try func(http.ResponseWriter, *http.Request) bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if s.limiter.Blocked(ip) {
			w.Header().Set("Retry-After", "300")
			writeErr(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		if try(w, r) {
			return
		}
		if s.limiter.Fail(ip) {
			s.audit(r.Context(), "anonymous", "auth.lockout", "ip/"+ip, "", map[string]string{"path": r.URL.Path})
		}
		writeErr(w, http.StatusUnauthorized, "missing, invalid or expired credentials")
	})
}

// ---- helpers ----

var (
	writeJSON = httpx.WriteJSON
	writeErr  = httpx.WriteErr
	decode    = httpx.Decode
	errLines  = httpx.ErrLines
	clientIP  = httpx.ClientIP
)

func (s *Server) raw(f func() []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(f())
	}
}

func (s *Server) audit(ctx context.Context, actor, action, target, entity string, payload any) {
	if payload == nil {
		payload = map[string]any{}
	}
	if err := s.store.AppendAudit(context.WithoutCancel(ctx), actor, action, target, entity, payload); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

// writeStoreErr maps store errors to HTTP without leaking internals.
func (s *Server) writeStoreErr(w http.ResponseWriter, err error, conflictMsg string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, conflictMsg)
	default:
		s.log.Error("store error", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}
