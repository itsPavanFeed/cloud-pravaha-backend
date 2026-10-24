// Package githubapp authenticates to GitHub as a GitHub App and verifies its
// webhook deliveries.
//
// The tenant plane signs a short-lived app JWT (RS256, 9 minutes) with the
// app's private key and exchanges it for an installation access token (one
// hour), which is cached in memory only. No long-lived user token is needed.
package githubapp

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DefaultAPI = "https://api.github.com"

// ParsePrivateKey accepts the PEM file GitHub generates (PKCS#1) or PKCS#8.
func ParsePrivateKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key is not an RSA key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key is not an RSA key")
	}
	return rk, nil
}

// AppJWT signs the token GitHub expects from an app: iss = app ID, issued 60s
// in the past (clock skew), valid for 9 minutes (GitHub allows at most 10).
func AppJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	c, _ := json.Marshal(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(), "iss": strconv.FormatInt(appID, 10)})
	signing := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// VerifySignature checks X-Hub-Signature-256 ("sha256=<hex HMAC of the body>").
func VerifySignature(secret, body []byte, header string) bool {
	got, ok := strings.CutPrefix(header, "sha256=")
	if !ok || len(secret) == 0 {
		return false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return hmac.Equal(sig, m.Sum(nil))
}

// App is one GitHub App's credentials.
type App struct {
	ID  int64
	Key *rsa.PrivateKey
	API string // https://api.github.com or https://ghe.example.com/api/v3
	HC  *http.Client

	mu     sync.Mutex
	tokens map[int64]cached
}

type cached struct {
	token   string
	expires time.Time
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("GitHub returned %d: %s", e.Status, e.Message) }

func (a *App) api() string {
	if a.API == "" {
		return DefaultAPI
	}
	return strings.TrimRight(a.API, "/")
}

func (a *App) call(ctx context.Context, method, path, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, a.api()+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	hc := a.HC
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
		}
		json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = resp.Status
		}
		return &APIError{Status: resp.StatusCode, Message: e.Message}
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (a *App) jwt() (string, error) { return AppJWT(a.ID, a.Key, time.Now()) }

// Info is the app as GitHub describes it.
type Info struct {
	ID          int64                  `json:"id"`
	Slug        string                 `json:"slug"`
	Name        string                 `json:"name"`
	Owner       struct{ Login string } `json:"owner"`
	HTMLURL     string                 `json:"html_url"`
	Events      []string               `json:"events"`
	Permissions map[string]string      `json:"permissions"`
}

func (a *App) Info(ctx context.Context) (*Info, error) {
	j, err := a.jwt()
	if err != nil {
		return nil, err
	}
	var i Info
	return &i, a.call(ctx, http.MethodGet, "/app", j, &i)
}

// Installation is where the app is installed.
type Installation struct {
	ID                  int64                  `json:"id"`
	Account             struct{ Login string } `json:"account"`
	RepositorySelection string                 `json:"repository_selection"`
	Permissions         map[string]string      `json:"permissions"`
	Events              []string               `json:"events"`
	SuspendedAt         *time.Time             `json:"suspended_at"`
}

// RepoInstallation finds the installation that covers owner/name.
func (a *App) RepoInstallation(ctx context.Context, repo string) (*Installation, error) {
	j, err := a.jwt()
	if err != nil {
		return nil, err
	}
	owner, name, ok := strings.Cut(repo, "/")
	if !ok {
		return nil, errors.New("repo must be owner/name")
	}
	var i Installation
	return &i, a.call(ctx, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/installation", j, &i)
}

func (a *App) Installations(ctx context.Context) ([]Installation, error) {
	j, err := a.jwt()
	if err != nil {
		return nil, err
	}
	var is []Installation
	return is, a.call(ctx, http.MethodGet, "/app/installations?per_page=100", j, &is)
}

// Token returns an installation access token, cached until five minutes
// before it expires.
func (a *App) Token(ctx context.Context, installationID int64) (string, error) {
	a.mu.Lock()
	if c, ok := a.tokens[installationID]; ok && time.Until(c.expires) > 5*time.Minute {
		a.mu.Unlock()
		return c.token, nil
	}
	a.mu.Unlock()
	j, err := a.jwt()
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.call(ctx, http.MethodPost, "/app/installations/"+strconv.FormatInt(installationID, 10)+"/access_tokens", j, &out); err != nil {
		return "", err
	}
	a.mu.Lock()
	if a.tokens == nil {
		a.tokens = map[int64]cached{}
	}
	a.tokens[installationID] = cached{out.Token, out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}

// RepoAccess checks the installation token can read a repository.
func (a *App) RepoAccess(ctx context.Context, installationID int64, repo string) (defaultBranch string, private bool, err error) {
	tok, err := a.Token(ctx, installationID)
	if err != nil {
		return "", false, err
	}
	var r struct {
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
	}
	owner, name, _ := strings.Cut(repo, "/")
	err = a.call(ctx, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), tok, &r)
	return r.DefaultBranch, r.Private, err
}
