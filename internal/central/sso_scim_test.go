package central

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/config"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/oidc"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
)

// fakeIdP is a minimal OIDC provider: discovery, RS256 JWKS, and a token
// endpoint that enforces PKCE.
type fakeIdP struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	mu    sync.Mutex
	codes map[string]map[string]string // code -> challenge, nonce, email, verified
}

func newIdP(t *testing.T) *fakeIdP {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: k, codes: map[string]map[string]string{}}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"issuer": f.srv.URL, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes())}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		c := f.codes[r.Form.Get("code")]
		delete(f.codes, r.Form.Get("code"))
		f.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if c == nil || base64.RawURLEncoding.EncodeToString(sum[:]) != c["challenge"] || r.Form.Get("client_id") != "pravaha" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"id_token": f.idToken(c["nonce"], c["email"], c["verified"] == "true")})
	})
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) idToken(nonce, email string, verified bool) string {
	b64 := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	now := time.Now().Unix()
	signing := b64(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"}) + "." + b64(map[string]any{
		"iss": f.srv.URL, "aud": "pravaha", "sub": "idp|" + email, "email": email, "email_verified": verified,
		"nonce": nonce, "iat": now, "nbf": now, "exp": now + 300})
	h := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, h[:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// authorize plays the user signing in at the IdP and returns the callback URL.
func (f *fakeIdP) authorize(authURL, email string, verified bool) string {
	u, _ := url.Parse(authURL)
	q := u.Query()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	f.mu.Lock()
	f.codes[code] = map[string]string{"challenge": q.Get("code_challenge"), "nonce": q.Get("nonce"), "email": email, "verified": fmt.Sprint(verified)}
	f.mu.Unlock()
	return q.Get("redirect_uri") + "?code=" + code + "&state=" + url.QueryEscape(q.Get("state"))
}

func testServer(t *testing.T, issuer string) (*Server, *Store, *httptest.Server) {
	dbURL := os.Getenv("PRAVAHA_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("PRAVAHA_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	st, err := OpenStore(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	k, _ := oidc.GenerateKey()
	front := httptest.NewUnstartedServer(nil)
	front.Start()
	t.Cleanup(front.Close)
	iss, _ := oidc.New(front.URL, k)
	cert, key := selfSigned(t)
	cfg := &config.Central{PublicURL: front.URL, InsecureHTTP: true, ClientCert: cert, ClientKey: key,
		OIDCIssuer: issuer, OIDCClientID: "pravaha", OIDCRedirectURL: front.URL + "/auth/callback", OIDCLabel: "SSO"}
	srv, err := New(cfg, st, iss, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	front.Config.Handler = srv.Handler()
	return srv, st, front
}

func selfSigned(t *testing.T) (string, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "c.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(filepath.Join(dir, "k.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
}

func browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// login runs the whole browser flow and returns where central sent the browser.
func login(t *testing.T, b *http.Client, front string, idp *fakeIdP, email string, verified bool) string {
	resp, err := b.Get(front + "/auth/login")
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %v %v", err, resp)
	}
	cb := idp.authorize(resp.Header.Get("Location"), email, verified)
	resp, err = b.Get(cb)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("callback: %v %v", err, resp)
	}
	return resp.Header.Get("Location")
}

func TestSSOAndSCIM(t *testing.T) {
	idp := newIdP(t)
	_, st, front := testServer(t, idp.srv.URL)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	alice := "alice" + suffix + "@sso.test"
	st.EnsureUser(ctx, alice, "", false, "test")

	// The full SSO flow ends in a one-time code that becomes a session token.
	b := browser()
	loc := login(t, b, front.URL, idp, alice, true)
	if !strings.HasPrefix(loc, "/#/sso/") {
		t.Fatalf("expected a sign-in code, got %s", loc)
	}
	code := strings.TrimPrefix(loc, "/#/sso/")
	tok := exchange(t, front.URL, code, 200)
	if status(t, front.URL+"/api/v1/me", tok) != 200 {
		t.Fatal("session token does not work")
	}
	exchange(t, front.URL, code, 401) // single use

	// Unknown users, unverified emails and forged state are refused.
	if loc := login(t, browser(), front.URL, idp, "nobody"+suffix+"@sso.test", true); !strings.Contains(loc, "sso_error=no_access") {
		t.Fatalf("unknown user: %s", loc)
	}
	if loc := login(t, browser(), front.URL, idp, alice, false); !strings.Contains(loc, "sso_error=email_not_verified") {
		t.Fatalf("unverified email: %s", loc)
	}
	resp, _ := browser().Get(front.URL + "/auth/login")
	cb := idp.authorize(resp.Header.Get("Location"), alice, true)
	resp, _ = browser().Get(cb) // a different browser: no state cookie
	if !strings.Contains(resp.Header.Get("Location"), "state_mismatch") {
		t.Fatalf("login CSRF: %s", resp.Header.Get("Location"))
	}

	// SCIM: provision a user, map a group to a role, then deactivate.
	scim, _ := secure.NewToken("s")
	st.CreateSCIMToken(ctx, "idp", "test", secure.HashToken(scim))
	tenant, _ := st.CreateTenant(ctx, &Tenant{Slug: "t" + suffix[len(suffix)-8:], Name: "T", BackendURL: "https://t.example", CreatedBy: "test"})
	bob := "bob" + suffix + "@sso.test"
	var user map[string]any
	scimDo(t, front.URL, scim, "POST", "/scim/v2/Users", map[string]any{"userName": bob, "displayName": "Bob"}, 201, &user)
	scimDo(t, front.URL, "pvh_s_wrong", "GET", "/scim/v2/Users", nil, 401, nil)
	var group map[string]any
	scimDo(t, front.URL, scim, "POST", "/scim/v2/Groups", map[string]any{"displayName": "pravaha:" + tenant.Slug + ":finops",
		"members": []map[string]string{{"value": user["id"].(string)}}}, 201, &group)
	scimDo(t, front.URL, scim, "POST", "/scim/v2/Groups", map[string]any{"displayName": "pravaha:" + tenant.Slug + ":root"}, 400, nil)
	u, _ := st.UserByEmail(ctx, bob)
	if p, _ := st.Principal(ctx, u, tenant.Slug); p == nil || !p.HasTenantRole(identity.FinOps) {
		t.Fatal("group membership did not grant finops")
	}
	scimDo(t, front.URL, scim, "PATCH", "/scim/v2/Groups/"+group["id"].(string), map[string]any{"schemas": []string{scimPatch},
		"Operations": []map[string]any{{"op": "remove", "path": `members[value eq "` + user["id"].(string) + `"]`}}}, 200, nil)
	if p, _ := st.Principal(ctx, u, tenant.Slug); p != nil {
		t.Fatal("removing the group member did not revoke the role")
	}
	// Deactivation revokes every token.
	alu, _ := st.UserByEmail(ctx, alice)
	scimDo(t, front.URL, scim, "PATCH", "/scim/v2/Users/"+alu.ID, map[string]any{"schemas": []string{scimPatch},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": false}}}, 200, nil)
	if status(t, front.URL+"/api/v1/me", tok) != 401 {
		t.Fatal("a deactivated user's session still works")
	}
	if loc := login(t, browser(), front.URL, idp, alice, true); !strings.Contains(loc, "no_access") {
		t.Fatal("a deactivated user can sign in")
	}
}

func exchange(t *testing.T, front, code string, want int) string {
	resp, err := http.Post(front+"/api/v1/auth/exchange", "application/json", strings.NewReader(`{"code":"`+code+`"}`))
	if err != nil || resp.StatusCode != want {
		t.Fatalf("exchange: want %d, got %v %v", want, resp.StatusCode, err)
	}
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	s, _ := out["secret"].(string)
	return s
}

func status(t *testing.T, u, tok string) int {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode
}

func scimDo(t *testing.T, front, tok, method, path string, body any, want int, out any) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, front+path, r)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != want {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: want %d, got %d %s %v", method, path, want, resp.StatusCode, b, err)
	}
	if out != nil {
		json.NewDecoder(resp.Body).Decode(out)
	}
}
