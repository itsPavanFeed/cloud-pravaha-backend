// Package central is the central plane: it serves the frontend, authenticates
// users, keeps the tenant directory (tenants, entities, memberships) and routes
// each request to the right tenant plane.
//
// Routing ("the wrapper"): /api/v1/t/{tenant}/<path> is forwarded to that
// tenant's backend as /api/v1/<path> over mTLS. The user's token never leaves
// central; instead central attaches a 60-second ES256 assertion naming the user,
// their roles in that tenant, and the exact method and path.
package central

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/certs"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/config"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/envfile"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/httpx"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
)

const assertionHeader = "X-Pravaha-Assertion"

var (
	emailRe   = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$|^[A-Za-z0-9._%+-]{1,64}@[a-z0-9-]{1,63}$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9 ._'&()-]{1,80}$`)
	tokNameRe = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)
	maxTTL    = 90 * 24 * time.Hour
)

type Server struct {
	cfg      *config.Central
	store    *Store
	issuer   *oidc.Issuer
	cert     *certs.KeyPair // mTLS client identity, reloaded when rotated
	log      *slog.Logger
	limiter  *httpx.Limiter
	hookBase atomic.Value // string: public webhook base URL from PRAVAHA_ENV_FILE
	// hookLimiter blocks addresses that send unsigned or rejected webhooks.
	hookLimiter *httpx.Limiter

	mu         sync.Mutex
	transports map[string]*tenantTransport
	sso        oidcProvider
}

type tenantTransport struct {
	key string // backend URL + CA, to rebuild when the tenant record changes
	rt  http.RoundTripper
}

func New(cfg *config.Central, st *Store, iss *oidc.Issuer, log *slog.Logger) (*Server, error) {
	cert, err := certs.NewKeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("loading mTLS client certificate: %w", err)
	}
	return &Server{cfg: cfg, store: st, issuer: iss, cert: cert, log: log,
		limiter: httpx.NewLimiter(10, time.Minute, 5*time.Minute), hookLimiter: httpx.NewLimiter(30, time.Minute, 10*time.Minute), transports: map[string]*tenantTransport{}}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		httpx.WriteJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(s.issuer.JWKS())
	})

	// SSO (OIDC) and SCIM provisioning.
	mux.HandleFunc("GET /api/v1/auth/config", s.authConfig)
	mux.HandleFunc("GET /auth/login", s.ssoLogin)
	mux.HandleFunc("GET /auth/callback", s.ssoCallback)
	mux.HandleFunc("POST /api/v1/auth/exchange", s.authExchange)
	mux.HandleFunc("POST /webhooks/github/{tenant}", s.githubWebhook)
	sc := s.scimAuth
	mux.Handle("GET /scim/v2/ServiceProviderConfig", sc(s.scimConfig))
	mux.Handle("GET /scim/v2/Users", sc(s.scimListUsers))
	mux.Handle("POST /scim/v2/Users", sc(s.scimCreateUser))
	mux.Handle("GET /scim/v2/Users/{id}", sc(s.scimGetUser))
	mux.Handle("PUT /scim/v2/Users/{id}", sc(s.scimUpdateUser))
	mux.Handle("PATCH /scim/v2/Users/{id}", sc(s.scimUpdateUser))
	mux.Handle("DELETE /scim/v2/Users/{id}", sc(s.scimDeleteUser))
	mux.Handle("GET /scim/v2/Groups", sc(s.scimListGroups))
	mux.Handle("POST /scim/v2/Groups", sc(s.scimCreateGroup))
	mux.Handle("GET /scim/v2/Groups/{id}", sc(s.scimGetGroup))
	mux.Handle("PATCH /scim/v2/Groups/{id}", sc(s.scimPatchGroup))
	mux.Handle("DELETE /scim/v2/Groups/{id}", sc(s.scimDeleteGroup))

	a := s.auth
	mux.Handle("POST /api/v1/auth/logout", a(s.logout))
	mux.Handle("GET /api/v1/me", a(s.me))
	mux.Handle("GET /api/v1/me/tokens", a(s.listOwnTokens))
	mux.Handle("POST /api/v1/me/tokens", a(s.createOwnToken))
	mux.Handle("DELETE /api/v1/me/tokens/{id}", a(s.revokeOwnToken))

	mux.Handle("GET /api/v1/tenants", a(s.listTenants))
	mux.Handle("POST /api/v1/tenants", a(s.onboardTenant))
	mux.Handle("GET /api/v1/tenants/{tenant}", a(s.getTenant))
	mux.Handle("PUT /api/v1/tenants/{tenant}", a(s.updateTenant))
	mux.Handle("GET /api/v1/tenants/{tenant}/health", a(s.tenantHealth))
	mux.Handle("GET /api/v1/tenants/{tenant}/entities", a(s.listEntities))
	mux.Handle("POST /api/v1/tenants/{tenant}/entities", a(s.createEntity))
	mux.Handle("GET /api/v1/tenants/{tenant}/bus", a(s.listBUs))
	mux.Handle("POST /api/v1/tenants/{tenant}/bus", a(s.createBU))
	mux.Handle("GET /api/v1/tenants/{tenant}/members", a(s.listMembers))
	mux.Handle("POST /api/v1/tenants/{tenant}/members", a(s.addMember))
	mux.Handle("DELETE /api/v1/tenants/{tenant}/members/{id}", a(s.removeMember))
	mux.Handle("POST /api/v1/tenants/{tenant}/tokens", a(s.issueMemberToken))

	// The wrapper: everything under /api/v1/t/{tenant}/ goes to that tenant plane.
	mux.Handle("/api/v1/t/{tenant}/{rest...}", a(s.proxy))

	if s.cfg.WebDir != "" {
		mux.Handle("/", httpx.SPA(s.cfg.WebDir))
	}
	return httpx.SecurityHeaders(!s.cfg.InsecureHTTP, mux)
}

func (s *Server) Run(ctx context.Context) error {
	var tlsCfg *tls.Config
	if !s.cfg.InsecureHTTP {
		kp, err := certs.NewKeyPair(s.cfg.TLSCert, s.cfg.TLSKey)
		if err != nil {
			return fmt.Errorf("TLS certificate: %w", err)
		}
		tlsCfg = certs.ServerConfig(kp, nil)
	} else {
		s.log.Warn("central serving plain HTTP on loopback for local development only", "listen", s.cfg.Listen)
	}
	if s.cfg.EnvFile != "" {
		s.loadEnvFile()
		go envfile.Watch(ctx, 2*time.Second, s.loadEnvFile, func() []string { return []string{s.cfg.EnvFile} })
	}
	s.log.Info("central plane serving", "listen", s.cfg.Listen, "public_url", s.cfg.PublicURL)
	return httpx.Serve(ctx, s.log, s.cfg.Listen, s.Handler(), tlsCfg, "", "")
}

// loadEnvFile picks up PRAVAHA_WEBHOOK_BASE_URL from the env file, so a new
// tunnel or ingress address takes effect without a restart.
func (s *Server) loadEnvFile() {
	m, err := envfile.Read(s.cfg.EnvFile)
	if err != nil {
		s.log.Warn("reading env file failed", "file", s.cfg.EnvFile, "err", err)
		return
	}
	v := strings.TrimRight(m["PRAVAHA_WEBHOOK_BASE_URL"], "/")
	if u, err := url.Parse(v); v != "" && (err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "") {
		s.log.Warn("ignoring PRAVAHA_WEBHOOK_BASE_URL in env file: must be an https origin", "value", v)
		return
	}
	if old, _ := s.hookBase.Load().(string); old != v {
		s.hookBase.Store(v)
		s.log.Info("webhook base URL", "url", v, "from", s.cfg.EnvFile)
	}
}

// webhookBase is where Git hosts send webhooks: the env file, then the
// environment, then the public URL.
func (s *Server) webhookBase() string {
	if v, _ := s.hookBase.Load().(string); v != "" {
		return v
	}
	if s.cfg.WebhookBaseURL != "" {
		return s.cfg.WebhookBaseURL
	}
	return s.cfg.PublicURL
}

// ---- auth ----

type ctxKey struct{}

func current(r *http.Request) *User { return r.Context().Value(ctxKey{}).(*User) }

func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httpx.ClientIP(r)
		if s.limiter.Blocked(ip) {
			w.Header().Set("Retry-After", "300")
			httpx.WriteErr(w, http.StatusTooManyRequests, "too many failed authentication attempts")
			return
		}
		tok := httpx.Bearer(r)
		var u *User
		var err error
		if strings.HasPrefix(tok, "pvh_u_") {
			u, err = s.store.UserByToken(r.Context(), secure.HashToken(tok))
		}
		if u == nil || err != nil {
			if s.limiter.Fail(ip) {
				s.audit(r.Context(), "anonymous", "auth.lockout", "ip/"+ip, "", map[string]string{"path": r.URL.Path})
			}
			httpx.WriteErr(w, http.StatusUnauthorized, "missing, invalid or expired token")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

func (s *Server) audit(ctx context.Context, actor, action, target, tenant string, payload any) {
	if payload == nil {
		payload = map[string]any{}
	}
	if err := s.store.AppendAudit(context.WithoutCancel(ctx), actor, action, target, tenant, payload); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}

func (s *Server) storeErr(w http.ResponseWriter, err error, conflict string) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, ErrConflict):
		httpx.WriteErr(w, http.StatusConflict, conflict)
	default:
		s.log.Error("store error", "err", err)
		httpx.WriteErr(w, http.StatusInternalServerError, "internal error")
	}
}

// tenantFor loads {tenant} and the caller's roles in it. Platform admins act as
// tenant admins (and more) in every tenant.
func (s *Server) tenantFor(w http.ResponseWriter, r *http.Request, needAdmin bool) (*Tenant, *identity.Principal) {
	u := current(r)
	t, err := s.store.Tenant(r.Context(), r.PathValue("tenant"))
	if err != nil {
		s.storeErr(w, err, "")
		return nil, nil
	}
	p, err := s.store.Principal(r.Context(), u, t.Slug)
	if err != nil {
		s.storeErr(w, err, "")
		return nil, nil
	}
	if p == nil && !u.PlatformAdmin {
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return nil, nil
	}
	if needAdmin && !u.PlatformAdmin && !p.HasTenantRole(identity.TenantAdmin) {
		httpx.WriteErr(w, http.StatusForbidden, "this needs the tenant_admin role")
		return nil, nil
	}
	if p == nil {
		p = &identity.Principal{Subject: u.Email, Tenant: t.Slug, EntityRoles: map[string][]string{}}
	}
	return t, p
}

// ---- me ----

type meTenant struct {
	Slug          string     `json:"slug"`
	Name          string     `json:"name"`
	TenantRoles   []string   `json:"tenant_roles"`
	PlatformAdmin bool       `json:"platform_admin,omitempty"`
	Entities      []meEntity `json:"entities"`
}

type meEntity struct {
	Slug  string   `json:"slug"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"` // granted on the entity (inherited by its BUs)
	BUs   []meBU   `json:"bus"`
}

type meBU struct {
	Slug  string   `json:"slug"`
	Name  string   `json:"name"`
	Roles []string `json:"roles"` // effective in this BU
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	slugs, err := s.store.UserTenants(r.Context(), u.ID)
	if u.PlatformAdmin && err == nil {
		var all []*Tenant
		if all, err = s.store.ListTenants(r.Context()); err == nil {
			slugs = slugs[:0]
			for _, t := range all {
				slugs = append(slugs, t.Slug)
			}
		}
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	tenants := []meTenant{}
	for _, slug := range slugs {
		t, err := s.store.Tenant(r.Context(), slug)
		if err != nil {
			continue
		}
		p, _ := s.store.Principal(r.Context(), u, slug)
		if p == nil {
			continue
		}
		ents, _ := s.store.Entities(r.Context(), t.ID)
		bus, _ := s.store.BUs(r.Context(), t.ID)
		mt := meTenant{Slug: t.Slug, Name: t.Name, TenantRoles: p.TenantRoles, PlatformAdmin: p.PlatformAdmin, Entities: []meEntity{}}
		for _, e := range ents {
			me := meEntity{Slug: e.Slug, Name: e.Name, Roles: orEmpty(p.EntityRoles[e.Slug]), BUs: []meBU{}}
			for _, b := range bus {
				if b.Entity != e.Slug {
					continue
				}
				if roles := p.BURoles[b.Slug]; len(roles) > 0 || p.SeesAllBUs() {
					me.BUs = append(me.BUs, meBU{Slug: b.Slug, Name: b.Name, Roles: orEmpty(roles)})
				}
			}
			if len(me.BUs) > 0 || len(me.Roles) > 0 || p.SeesAllBUs() {
				mt.Entities = append(mt.Entities, me)
			}
		}
		tenants = append(tenants, mt)
	}
	httpx.WriteJSON(w, 200, map[string]any{"user": u, "tenants": tenants})
}

func orEmpty(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func (s *Server) listOwnTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := s.store.ListTokens(r.Context(), current(r).ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, ts)
}

type tokenBody struct {
	Email   string `json:"email,omitempty"`
	Name    string `json:"name"`
	TTLDays int    `json:"ttl_days"`
}

func (b *tokenBody) check(w http.ResponseWriter) (time.Duration, bool) {
	ttl := time.Duration(b.TTLDays) * 24 * time.Hour
	if !tokNameRe.MatchString(b.Name) || ttl <= 0 || ttl > maxTTL {
		httpx.WriteErr(w, 422, "token name is required and ttl_days must be between 1 and 90")
		return 0, false
	}
	return ttl, true
}

func (s *Server) createOwnToken(w http.ResponseWriter, r *http.Request) {
	var b tokenBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	ttl, ok := b.check(w)
	if !ok {
		return
	}
	u := current(r)
	s.issueToken(w, r, u, b.Name, ttl, "")
}

func (s *Server) issueToken(w http.ResponseWriter, r *http.Request, u *User, name string, ttl time.Duration, tenant string) {
	plain, err := secure.NewToken("u")
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	t, err := s.store.CreateToken(r.Context(), u.ID, name, current(r).Email, secure.HashToken(plain), time.Now().Add(ttl))
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "token.create", "user/"+u.Email, tenant, map[string]any{"token": t.ID, "expires_at": t.ExpiresAt})
	httpx.WriteJSON(w, 201, map[string]any{"token": t, "user": u.Email, "secret": plain})
}

func (s *Server) revokeOwnToken(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	if err := s.store.RevokeToken(r.Context(), u.ID, r.PathValue("id")); err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), u.Email, "token.revoke", "user/"+u.Email, "", map[string]string{"token": r.PathValue("id")})
	w.WriteHeader(http.StatusNoContent)
}

// ---- tenants (platform admins) ----

func platformAdmin(w http.ResponseWriter, r *http.Request) bool {
	if !current(r).PlatformAdmin {
		httpx.WriteErr(w, http.StatusForbidden, "this needs a platform admin")
		return false
	}
	return true
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	ts, err := s.store.ListTenants(r.Context())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, ts)
}

type tenantBody struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	BackendURL  string `json:"backend_url"`
	ServerCAPEM string `json:"server_ca_pem"`
	AdminEmail  string `json:"admin_email"`
}

func (b *tenantBody) validate(create bool) []string {
	var probs []string
	if create && !identity.SlugRe.MatchString(b.Slug) {
		probs = append(probs, "slug must be lowercase letters, digits and dashes (2-32)")
	}
	if !nameRe.MatchString(b.Name) {
		probs = append(probs, "name is required")
	}
	if u, err := url.Parse(b.BackendURL); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" {
		probs = append(probs, "backend_url must be the tenant plane's https:// base URL")
	}
	if b.ServerCAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(b.ServerCAPEM)) {
		probs = append(probs, "server_ca_pem must contain PEM certificates")
	}
	if create && !emailRe.MatchString(b.AdminEmail) {
		probs = append(probs, "admin_email must be the first tenant admin's email")
	}
	return probs
}

// onboardTenant registers a tenant plane and its first tenant admin, and
// returns the settings that plane must be started with.
func (s *Server) onboardTenant(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var b tenantBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	if probs := b.validate(true); len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid tenant", probs...)
		return
	}
	by := current(r).Email
	t, err := s.store.CreateTenant(r.Context(), &Tenant{Slug: b.Slug, Name: b.Name, BackendURL: strings.TrimRight(b.BackendURL, "/"), ServerCAPEM: b.ServerCAPEM, CreatedBy: by})
	if err != nil {
		s.storeErr(w, err, "a tenant with that slug exists")
		return
	}
	admin, err := s.store.EnsureUser(r.Context(), b.AdminEmail, "", false, by)
	if err == nil {
		_, err = s.store.AddMembership(r.Context(), admin.ID, t.ID, nil, nil, identity.TenantAdmin, by)
	}
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), by, "tenant.onboard", "tenant/"+t.Slug, t.Slug, map[string]string{"backend_url": t.BackendURL, "admin": b.AdminEmail})
	httpx.WriteJSON(w, 201, map[string]any{
		"tenant": t,
		"tenant_plane_settings": map[string]string{
			"PRAVAHA_TENANT":      t.Slug,
			"PRAVAHA_CENTRAL_URL": s.cfg.PublicURL,
			"PRAVAHA_PUBLIC_URL":  t.BackendURL,
			"note":                "Also set PRAVAHA_CENTRAL_CLIENT_CA to the CA that issued central's client certificate.",
		},
	})
}

func (s *Server) getTenant(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t != nil {
		httpx.WriteJSON(w, 200, t)
	}
}

func (s *Server) updateTenant(w http.ResponseWriter, r *http.Request) {
	if !platformAdmin(w, r) {
		return
	}
	var b tenantBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	if probs := b.validate(false); len(probs) > 0 {
		httpx.WriteErr(w, 422, "invalid tenant", probs...)
		return
	}
	t, err := s.store.UpdateTenant(r.Context(), &Tenant{Slug: r.PathValue("tenant"), Name: b.Name, BackendURL: strings.TrimRight(b.BackendURL, "/"), ServerCAPEM: b.ServerCAPEM})
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "tenant.update", "tenant/"+t.Slug, t.Slug, map[string]string{"backend_url": t.BackendURL})
	httpx.WriteJSON(w, 200, t)
}

// tenantHealth checks central can reach the tenant plane over mTLS and that
// it identifies as the same tenant.
func (s *Server) tenantHealth(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	rt, err := s.transport(t)
	if err != nil {
		httpx.WriteJSON(w, 200, map[string]any{"reachable": false, "error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, t.BackendURL+"/healthz", nil)
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		httpx.WriteJSON(w, 200, map[string]any{"reachable": false, "error": err.Error()})
		return
	}
	defer resp.Body.Close()
	var h struct{ Status, Tenant string }
	json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h)
	ok := resp.StatusCode == 200 && h.Tenant == t.Slug
	res := map[string]any{"reachable": ok, "status": resp.StatusCode, "reported_tenant": h.Tenant}
	if !ok && h.Tenant != t.Slug {
		res["error"] = "the backend at this URL is not configured as tenant " + t.Slug
	}
	httpx.WriteJSON(w, 200, res)
}

// ---- entities & members (tenant admins, or platform admins) ----

func (s *Server) listEntities(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t == nil {
		return
	}
	es, err := s.store.Entities(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, es)
}

func (s *Server) createEntity(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct{ Slug, Name string }
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !identity.SlugRe.MatchString(b.Slug) || !nameRe.MatchString(b.Name) {
		httpx.WriteErr(w, 422, "slug must be lowercase letters, digits and dashes (2-32) and name is required")
		return
	}
	e, err := s.store.CreateEntity(r.Context(), t.ID, b.Slug, b.Name, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "an entity with that slug exists")
		return
	}
	s.audit(r.Context(), current(r).Email, "entity.create", "entity/"+e.Slug, t.Slug, e)
	httpx.WriteJSON(w, 201, e)
}

func (s *Server) listBUs(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, false)
	if t == nil {
		return
	}
	bs, err := s.store.BUs(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, bs)
}

// createBU adds a business unit (a product) under an entity.
func (s *Server) createBU(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct{ Slug, Name, Entity string }
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !identity.SlugRe.MatchString(b.Slug) || !nameRe.MatchString(b.Name) {
		httpx.WriteErr(w, 422, "slug must be lowercase letters, digits and dashes (2-32) and name is required")
		return
	}
	e, err := s.store.Entity(r.Context(), t.ID, b.Entity)
	if err != nil {
		httpx.WriteErr(w, 422, "unknown entity "+b.Entity)
		return
	}
	bu, err := s.store.CreateBU(r.Context(), t.ID, e.ID, b.Slug, b.Name, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "a business unit with that slug exists")
		return
	}
	s.audit(r.Context(), current(r).Email, "bu.create", "bu/"+bu.Slug, t.Slug, bu)
	httpx.WriteJSON(w, 201, bu)
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	ms, err := s.store.TenantMembers(r.Context(), t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, ms)
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b struct{ Email, Name, Entity, BU, Role string }
	if !httpx.Decode(w, r, &b) {
		return
	}
	if !emailRe.MatchString(b.Email) {
		httpx.WriteErr(w, 422, "email is invalid")
		return
	}
	var entityID, buID *string
	scopeErr := "tenant-wide roles are " + strings.Join(identity.TenantRoles, ", ") + "; entity and business-unit roles are " + strings.Join(identity.ScopedRoles, ", ") + "; give at most one of entity or bu"
	switch {
	case b.Entity == "" && b.BU == "" && identity.IsTenantRole(b.Role):
	case b.Entity != "" && b.BU == "" && identity.IsScopedRole(b.Role):
		e, err := s.store.Entity(r.Context(), t.ID, b.Entity)
		if err != nil {
			httpx.WriteErr(w, 422, "unknown entity "+b.Entity)
			return
		}
		entityID = &e.ID
	case b.BU != "" && b.Entity == "" && identity.IsScopedRole(b.Role):
		bu, err := s.store.BUBySlug(r.Context(), t.ID, b.BU)
		if err != nil {
			httpx.WriteErr(w, 422, "unknown business unit "+b.BU)
			return
		}
		buID = &bu.ID
	default:
		httpx.WriteErr(w, 422, scopeErr)
		return
	}
	u, err := s.store.EnsureUser(r.Context(), b.Email, b.Name, false, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	m, err := s.store.AddMembership(r.Context(), u.ID, t.ID, entityID, buID, b.Role, current(r).Email)
	if err != nil {
		s.storeErr(w, err, "that membership exists")
		return
	}
	s.audit(r.Context(), current(r).Email, "member.add", "user/"+b.Email, t.Slug, m)
	httpx.WriteJSON(w, 201, m)
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	m, err := s.store.RemoveMembership(r.Context(), t.ID, r.PathValue("id"))
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "member.remove", "user/"+m.Email, t.Slug, m)
	w.WriteHeader(http.StatusNoContent)
}

// issueMemberToken lets a tenant admin hand a first token to a member. It is
// refused for anyone who also belongs to another tenant or is a platform admin,
// so a tenant admin can never impersonate people outside their tenant.
func (s *Server) issueMemberToken(w http.ResponseWriter, r *http.Request) {
	t, _ := s.tenantFor(w, r, true)
	if t == nil {
		return
	}
	var b tokenBody
	if !httpx.Decode(w, r, &b) {
		return
	}
	ttl, ok := b.check(w)
	if !ok {
		return
	}
	u, err := s.store.UserByEmail(r.Context(), b.Email)
	if err != nil {
		httpx.WriteErr(w, 422, "add the user as a member first")
		return
	}
	p, err := s.store.Principal(r.Context(), u, t.Slug)
	if err != nil || p == nil {
		httpx.WriteErr(w, 422, "add the user as a member first")
		return
	}
	only, err := s.store.OnlyInTenant(r.Context(), u.ID, t.ID)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if !current(r).PlatformAdmin && (!only || u.PlatformAdmin) {
		httpx.WriteErr(w, http.StatusForbidden, "this user belongs to other tenants or is a platform admin; they must create their own tokens")
		return
	}
	s.issueToken(w, r, u, b.Name, ttl, t.Slug)
}

// ---- the wrapper ----

func (s *Server) transport(t *Tenant) (http.RoundTripper, error) {
	key := t.BackendURL + "\x00" + t.ServerCAPEM
	s.mu.Lock()
	defer s.mu.Unlock()
	if tt := s.transports[t.Slug]; tt != nil && tt.key == key {
		return tt.rt, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, GetClientCertificate: s.cert.GetClientCertificate}
	if t.ServerCAPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(t.ServerCAPEM)) {
			return nil, errors.New("tenant server CA is invalid")
		}
		tc.RootCAs = pool
	}
	rt := &http.Transport{TLSClientConfig: tc, ResponseHeaderTimeout: 60 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 16}
	s.transports[t.Slug] = &tenantTransport{key: key, rt: rt}
	return rt, nil
}

const assistantTimeout = 5 * time.Minute

// proxy forwards /api/v1/t/{tenant}/<rest> to the tenant plane as /api/v1/<rest>.
func (s *Server) proxy(w http.ResponseWriter, r *http.Request) {
	u := current(r)
	slug := r.PathValue("tenant")
	t, err := s.store.Tenant(r.Context(), slug)
	if err != nil {
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	p, err := s.store.Principal(r.Context(), u, slug)
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if p == nil { // platform admins always get a principal
		// Same answer as an unknown tenant: membership is not discoverable.
		httpx.WriteErr(w, http.StatusNotFound, "not found")
		return
	}
	prefix := "/api/v1/t/" + slug
	escaped := r.URL.EscapedPath()
	if !strings.HasPrefix(escaped, prefix+"/") {
		httpx.WriteErr(w, http.StatusBadRequest, "bad path")
		return
	}
	path := "/api/v1" + strings.TrimPrefix(escaped, prefix)
	target, err := url.Parse(t.BackendURL + path)
	if err != nil {
		httpx.WriteErr(w, http.StatusBadRequest, "bad path")
		return
	}
	target.RawQuery = r.URL.RawQuery
	assertion, err := identity.SignAssertion(s.issuer, p, r.Method, target.EscapedPath(), time.Now())
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	rt, err := s.transport(t)
	if err != nil {
		httpx.WriteErr(w, http.StatusBadGateway, "tenant "+slug+" is misconfigured")
		return
	}
	if path == "/api/v1/assistant/ask" {
		// The tenant streams progress while the assistant works, which can
		// outlast the server's normal write timeout.
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(assistantTimeout + 30*time.Second))
	}
	rp := &httputil.ReverseProxy{
		Transport:     rt,
		FlushInterval: -1, // pass streamed responses through as they arrive
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL = target
			pr.Out.Host = target.Host
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")
			pr.Out.Header.Set(assertionHeader, assertion)
			pr.SetXForwarded()
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Warn("tenant plane unreachable", "tenant", slug, "err", err)
			httpx.WriteErr(w, http.StatusBadGateway, "tenant "+slug+" is unreachable")
		},
	}
	rp.ServeHTTP(w, r)
}
