// Package githubapp authenticates to GitHub as a GitHub App and verifies its
// webhook deliveries.
//
// The tenant plane signs a short-lived app JWT (RS256, 9 minutes) with the
// app's private key and exchanges it for an installation access token (one
// hour), which is cached in memory only. No long-lived user token is needed.
package githubapp

import (
	"bytes"
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
	return a.send(ctx, method, path, bearer, nil, out)
}

func (a *App) send(ctx context.Context, method, path, bearer string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.api()+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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

// ---- repository operations with an installation token ----

func repoPath(repo string) string {
	owner, name, _ := strings.Cut(repo, "/")
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name)
}

// Do calls the API as the installation.
func (a *App) Do(ctx context.Context, installationID int64, method, path string, body, out any) error {
	tok, err := a.Token(ctx, installationID)
	if err != nil {
		return err
	}
	return a.send(ctx, method, path, tok, body, out)
}

// SetStatus sets a commit status (state: pending, success, failure, error).
func (a *App) SetStatus(ctx context.Context, inst int64, repo, sha, state, context_, description, target string) error {
	if len(description) > 140 {
		description = description[:139] + "…"
	}
	body := map[string]string{"state": state, "context": context_, "description": description}
	if target != "" {
		body["target_url"] = target
	}
	return a.Do(ctx, inst, http.MethodPost, repoPath(repo)+"/statuses/"+url.PathEscape(sha), body, nil)
}

// Comment creates a pull request comment, or edits commentID when it is set.
func (a *App) Comment(ctx context.Context, inst int64, repo string, pr int, commentID int64, body string) (int64, error) {
	var out struct {
		ID int64 `json:"id"`
	}
	if commentID != 0 {
		err := a.Do(ctx, inst, http.MethodPatch, repoPath(repo)+"/issues/comments/"+strconv.FormatInt(commentID, 10), map[string]string{"body": body}, &out)
		if e, ok := err.(*APIError); !ok || e.Status != http.StatusNotFound {
			return commentID, err
		}
		// the comment was deleted: post a new one
	}
	err := a.Do(ctx, inst, http.MethodPost, repoPath(repo)+"/issues/"+strconv.Itoa(pr)+"/comments", map[string]string{"body": body}, &out)
	return out.ID, err
}

// PR is the part of a pull request the platform uses.
type PR struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	Title   string `json:"title"`
	HTMLURL string `json:"html_url"`
	Draft   bool   `json:"draft"`
	Merged  bool   `json:"merged"`
	User    struct {
		Login string `json:"login"`
	} `json:"user"`
	Head struct {
		SHA  string `json:"sha"`
		Ref  string `json:"ref"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string `json:"ref"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"base"`
}

func (a *App) GetPR(ctx context.Context, inst int64, repo string, n int) (*PR, error) {
	var p PR
	return &p, a.Do(ctx, inst, http.MethodGet, repoPath(repo)+"/pulls/"+strconv.Itoa(n), nil, &p)
}

// Merge merges a pull request, only if its head is still sha.
func (a *App) Merge(ctx context.Context, inst int64, repo string, n int, sha, title, message string) error {
	return a.Do(ctx, inst, http.MethodPut, repoPath(repo)+"/pulls/"+strconv.Itoa(n)+"/merge",
		map[string]string{"sha": sha, "merge_method": "squash", "commit_title": title, "commit_message": message}, nil)
}

// ---- self-service: branches, files and pull requests ----

// BranchSHA returns the commit a branch points at.
func (a *App) BranchSHA(ctx context.Context, inst int64, repo, branch string) (string, error) {
	var out struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	err := a.Do(ctx, inst, http.MethodGet, repoPath(repo)+"/git/ref/heads/"+branch, nil, &out)
	return out.Object.SHA, err
}

func (a *App) CreateBranch(ctx context.Context, inst int64, repo, branch, sha string) error {
	return a.Do(ctx, inst, http.MethodPost, repoPath(repo)+"/git/refs", map[string]string{"ref": "refs/heads/" + branch, "sha": sha}, nil)
}

// FileSHA returns a file's blob SHA on a branch ("" when it does not exist).
func (a *App) FileSHA(ctx context.Context, inst int64, repo, path, branch string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	err := a.Do(ctx, inst, http.MethodGet, repoPath(repo)+"/contents/"+escapePath(path)+"?ref="+url.QueryEscape(branch), nil, &out)
	if e, ok := err.(*APIError); ok && e.Status == http.StatusNotFound {
		return "", nil
	}
	return out.SHA, err
}

// PutFile creates or updates a file on a branch in one commit.
func (a *App) PutFile(ctx context.Context, inst int64, repo, path, branch, message string, content []byte, sha string) error {
	body := map[string]string{"message": message, "branch": branch, "content": base64.StdEncoding.EncodeToString(content)}
	if sha != "" {
		body["sha"] = sha
	}
	return a.Do(ctx, inst, http.MethodPut, repoPath(repo)+"/contents/"+escapePath(path), body, nil)
}

func (a *App) OpenPR(ctx context.Context, inst int64, repo, head, base, title, body string) (*PR, error) {
	var p PR
	return &p, a.Do(ctx, inst, http.MethodPost, repoPath(repo)+"/pulls", map[string]string{"head": head, "base": base, "title": title, "body": body}, &p)
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}
