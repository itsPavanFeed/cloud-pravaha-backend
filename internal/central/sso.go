package central

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/httpx"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// SSO with OpenID Connect: authorization code flow with PKCE.
//
//	/auth/login      creates a single-use flow (state, nonce, PKCE verifier) bound
//	                 to the browser by an HttpOnly cookie, then redirects to the IdP
//	/auth/callback   checks state against the cookie, exchanges the code with the
//	                 verifier, verifies the ID token (signature, iss, aud, exp,
//	                 nonce, verified email) and maps the email to an existing user
//	/api/v1/auth/exchange  turns a 60-second single-use code into a session token,
//	                 so the token never appears in a URL
//
// SSO only authenticates: access still comes from roles granted in Cloud Pravaha.

const (
	stateCookie    = "pravaha_sso_state"
	flowTTL        = 10 * time.Minute
	codeTTL        = 60 * time.Second
	sessionTTL     = 12 * time.Hour
	sessionToken   = "sso session"
	discoveryCache = time.Hour
)

type oidcProvider struct {
	mu       sync.Mutex
	fetched  time.Time
	authURL  string
	tokenURL string
	verifier *oidc.Verifier
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// provider loads (and caches) the IdP's discovery document and keys.
func (s *Server) provider(ctx context.Context, refresh bool) (*oidcProvider, error) {
	p := &s.sso
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier != nil && !refresh && time.Since(p.fetched) < discoveryCache {
		return p, nil
	}
	hc := &http.Client{Timeout: 10 * time.Second}
	get := func(u string, v any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("%s returned %s", u, resp.Status)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
	}
	var doc struct {
		Issuer   string `json:"issuer"`
		AuthURL  string `json:"authorization_endpoint"`
		TokenURL string `json:"token_endpoint"`
		JWKSURI  string `json:"jwks_uri"`
	}
	if err := get(s.cfg.OIDCIssuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, err
	}
	if strings.TrimRight(doc.Issuer, "/") != s.cfg.OIDCIssuer {
		return nil, errors.New("IdP discovery issuer does not match PRAVAHA_OIDC_ISSUER")
	}
	var jwks json.RawMessage
	if err := get(doc.JWKSURI, &jwks); err != nil {
		return nil, err
	}
	v, err := oidc.NewVerifier(s.cfg.OIDCIssuer, jwks)
	if err != nil {
		return nil, err
	}
	p.authURL, p.tokenURL, p.verifier, p.fetched = doc.AuthURL, doc.TokenURL, v, time.Now()
	return p, nil
}

func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, 200, map[string]any{"sso": s.cfg.OIDCIssuer != "", "label": s.cfg.OIDCLabel, "webhook_base_url": s.webhookBase()})
}

func (s *Server) ssoLogin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.OIDCIssuer == "" {
		http.NotFound(w, r)
		return
	}
	p, err := s.provider(r.Context(), false)
	if err != nil {
		s.log.Error("SSO provider unavailable", "err", err)
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	state, verifier, nonce := randToken(24), randToken(32), randToken(24)
	if err := s.store.CreateAuthFlow(r.Context(), state, verifier, nonce); err != nil {
		s.storeErr(w, err, "")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/auth", MaxAge: int(flowTTL.Seconds()),
		HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {s.cfg.OIDCClientID},
		"redirect_uri":          {s.cfg.OIDCRedirectURL},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.authURL, "?") {
		sep = "&"
	}
	http.Redirect(w, r, p.authURL+sep+q.Encode(), http.StatusFound)
}

func (s *Server) ssoFail(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, "/#/login?sso_error="+url.QueryEscape(reason), http.StatusFound)
}

func (s *Server) ssoCallback(w http.ResponseWriter, r *http.Request) {
	if s.cfg.OIDCIssuer == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	c, err := r.Cookie(stateCookie)
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/auth", MaxAge: -1, HttpOnly: true, Secure: !s.cfg.InsecureHTTP, SameSite: http.SameSiteLaxMode})
	if err != nil || state == "" || c.Value != state {
		s.ssoFail(w, r, "state_mismatch")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.ssoFail(w, r, "idp_"+e)
		return
	}
	verifier, nonce, err := s.store.TakeAuthFlow(ctx, state, flowTTL)
	if err != nil {
		s.ssoFail(w, r, "expired")
		return
	}
	p, err := s.provider(ctx, false)
	if err != nil {
		s.ssoFail(w, r, "provider_unavailable")
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {r.URL.Query().Get("code")}, "redirect_uri": {s.cfg.OIDCRedirectURL},
		"client_id": {s.cfg.OIDCClientID}, "code_verifier": {verifier}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.cfg.OIDCClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(s.cfg.OIDCClientID), url.QueryEscape(s.cfg.OIDCClientSecret))
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		s.ssoFail(w, r, "token_exchange")
		return
	}
	defer resp.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok) != nil || tok.IDToken == "" {
		s.ssoFail(w, r, "token_exchange")
		return
	}
	claims, err := p.verifier.Verify(tok.IDToken, s.cfg.OIDCClientID, time.Now())
	if err != nil && err.Error() == "unknown signing key" { // the IdP may have rotated keys
		if p, err2 := s.provider(ctx, true); err2 == nil {
			claims, err = p.verifier.Verify(tok.IDToken, s.cfg.OIDCClientID, time.Now())
		}
	}
	if err != nil || claims["nonce"] != nonce {
		s.log.Warn("SSO ID token rejected", "err", err)
		s.ssoFail(w, r, "invalid_token")
		return
	}
	email, _ := claims["email"].(string)
	email = strings.ToLower(strings.TrimSpace(email))
	verified, _ := claims["email_verified"].(bool)
	if email == "" || (!verified && !s.cfg.OIDCTrustUnverified) {
		s.ssoFail(w, r, "email_not_verified")
		return
	}
	if !s.domainAllowed(email) {
		s.ssoFail(w, r, "domain_not_allowed")
		return
	}
	u, err := s.store.UserByEmail(ctx, email)
	if err != nil || u.DisabledAt != nil {
		s.audit(ctx, "sso:"+email, "auth.sso_denied", "user/"+email, "", map[string]string{"reason": "no such user or disabled"})
		s.ssoFail(w, r, "no_access")
		return
	}
	code := randToken(32)
	if err := s.store.CreateAuthCode(ctx, secure.HashToken(code), u.ID, codeTTL); err != nil {
		s.ssoFail(w, r, "internal")
		return
	}
	s.audit(ctx, u.Email, "auth.sso_login", "user/"+u.Email, "", map[string]string{"issuer": s.cfg.OIDCIssuer})
	http.Redirect(w, r, "/#/sso/"+code, http.StatusFound)
}

func (s *Server) domainAllowed(email string) bool {
	if len(s.cfg.OIDCAllowedDomains) == 0 {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	for _, d := range s.cfg.OIDCAllowedDomains {
		if at >= 0 && email[at+1:] == d {
			return true
		}
	}
	return false
}

// authExchange swaps a one-time SSO code for a 12-hour session token.
func (s *Server) authExchange(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	if s.limiter.Blocked(ip) {
		httpx.WriteErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return
	}
	var b struct {
		Code string `json:"code"`
	}
	if !httpx.Decode(w, r, &b) {
		return
	}
	u, err := s.store.TakeAuthCode(r.Context(), secure.HashToken(b.Code))
	if err != nil {
		s.limiter.Fail(ip)
		httpx.WriteErr(w, http.StatusUnauthorized, "invalid or expired sign-in code")
		return
	}
	plain, err := secure.NewToken("u")
	if err != nil {
		s.storeErr(w, err, "")
		return
	}
	if _, err := s.store.CreateToken(r.Context(), u.ID, sessionToken, "sso", secure.HashToken(plain), time.Now().Add(sessionTTL)); err != nil {
		s.storeErr(w, err, "")
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"secret": plain, "expires_in": int(sessionTTL.Seconds())})
}

// logout revokes the token the request was made with.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.RevokeTokenByHash(r.Context(), secure.HashToken(httpx.Bearer(r))); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.storeErr(w, err, "")
		return
	}
	s.audit(r.Context(), current(r).Email, "auth.logout", "user/"+current(r).Email, "", nil)
	w.WriteHeader(http.StatusNoContent)
}
