package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client calls the central plane. Tenant-plane resources go through central's
// wrapper (/api/v1/t/{tenant}/...), exactly like the web console.
type Client struct {
	base   string
	token  string
	tenant string
	http   *http.Client
}

type APIError struct {
	Status  int
	Message string
	Details []string `json:"details"`
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("Cloud Pravaha API returned %d: %s", e.Status, e.Message)
	if len(e.Details) > 0 {
		msg += "\n- " + strings.Join(e.Details, "\n- ")
	}
	return msg
}

func IsNotFound(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Status == http.StatusNotFound
}

func NewClient(endpoint, token, tenant, caFile string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
		return nil, fmt.Errorf("endpoint must be the central plane's https URL (plain http only for localhost)")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s has no PEM certificates", caFile)
		}
		tc.RootCAs = pool
	}
	return &Client{base: u.String(), token: token, tenant: tenant,
		http: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}}}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "terraform-provider-pravaha")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 300 {
		e := &APIError{Status: resp.StatusCode, Message: resp.Status}
		var eb struct {
			Error   string   `json:"error"`
			Details []string `json:"details"`
		}
		if json.Unmarshal(b, &eb) == nil && eb.Error != "" {
			e.Message, e.Details = eb.Error, eb.Details
		}
		return e
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (c *Client) central(p string) string  { return "/api/v1/tenants/" + url.PathEscape(c.tenant) + p }
func (c *Client) inTenant(p string) string { return "/api/v1/t/" + url.PathEscape(c.tenant) + p }

// ---- API types (the subset the provider manages) ----

type Entity struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
}

type BU struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Entity string `json:"entity"`
}

type Member struct {
	ID     string `json:"id,omitempty"`
	Email  string `json:"email"`
	Entity string `json:"entity,omitempty"`
	BU     string `json:"bu,omitempty"`
	Role   string `json:"role"`
}

type Connection struct {
	ID       string          `json:"id,omitempty"`
	Name     string          `json:"name"`
	Cloud    json.RawMessage `json:"cloud"`
	Entities []string        `json:"entities"`
}

type Environment struct {
	ID           string `json:"id,omitempty"`
	Name         string `json:"name"`
	Entity       string `json:"entity"`
	Tier         string `json:"tier"`
	Connection   string `json:"connection"`
	RunnerPool   string `json:"runner_pool"`
	MaxDestroys  *int64 `json:"max_destroys"`
	AllowDestroy bool   `json:"allow_destroy"`
}

type PolicySet struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Scope   string `json:"scope"`
	Level   string `json:"level"`
	Module  string `json:"module"`
	Enabled *bool  `json:"enabled"`
}

type CatalogModule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Cloud       string   `json:"cloud"`
	Source      string   `json:"source"`
	Versions    []string `json:"versions"`
	Outputs     []string `json:"outputs"`
	Description string   `json:"description"`
}

// findBy lists a collection and returns the item whose key matches.
func findBy[T any](ctx context.Context, c *Client, path string, match func(T) bool) (*T, error) {
	var items []T
	if err := c.do(ctx, http.MethodGet, path, nil, &items); err != nil {
		return nil, err
	}
	for i := range items {
		if match(items[i]) {
			return &items[i], nil
		}
	}
	return nil, &APIError{Status: http.StatusNotFound, Message: "not found"}
}
