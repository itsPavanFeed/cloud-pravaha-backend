// Package config reads settings from the environment. Secrets come only from
// the environment (or files it points to), never from flags or config files
// that end up in shell history or repositories.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Server configures a tenant plane: one client's backend, database and state.
type Server struct {
	DatabaseURL string
	MasterKey   string
	Listen      string
	PublicURL   string // runners and clouds reach this plane here; it is the clouds' OIDC issuer
	TLSCert     string
	TLSKey      string
	CatalogDir  string
	TofuVersion string

	Tenant          string // this plane's tenant slug; assertions must name it
	CentralURL      string // where this plane reaches central to fetch its JWKS
	CentralIssuer   string // the iss central signs with (its public URL); defaults to CentralURL
	CentralCAFile   string // CA to trust when fetching central's JWKS (optional)
	CentralClientCA string // CA that signed central's mTLS client certificate
	CentralJWKSFile string // static JWKS instead of fetching it (optional)

	AllowLocalContracts bool // development only: contracts from a local directory

	BucketURL       string // s3://bucket[/prefix]?endpoint=...&region=... (optional)
	BucketAccessKey string
	BucketSecretKey string
	BucketCreate    bool // create the bucket on start (development)

	TemporalAddress   string // host:port of Temporal; empty = built-in orchestration
	TemporalNamespace string

	// The assistant (Claude with retrieval over the catalog, docs, policies and
	// the caller's stacks). Off unless an API key is configured: enabling it
	// sends that context to the Anthropic API.
	AssistantAPIKey    string
	AssistantBaseURL   string // optional gateway; server-side fallbacks are then off
	AssistantModel     string
	AssistantEffort    string // low | medium | high | xhigh | max
	AssistantDocsDir   string // extra Markdown files to index (README, runbooks)
	AssistantFallbacks bool

	// EnvFile is a writable .env holding integration settings (PRAVAHA_GITHUB_*);
	// they are watched and reloaded. Empty keeps them sealed in the database.
	EnvFile string
}

// Central configures the central plane: frontend, identity, tenant routing.
type Central struct {
	DatabaseURL  string
	MasterKey    string
	Listen       string
	PublicURL    string
	TLSCert      string
	TLSKey       string
	InsecureHTTP bool // only permitted on a loopback listener, for local development
	WebDir       string
	ClientCert   string // mTLS client certificate presented to tenant planes
	ClientKey    string

	// SSO (OpenID Connect). Empty issuer disables SSO.
	OIDCIssuer          string
	OIDCClientID        string
	OIDCClientSecret    string   // optional: public clients rely on PKCE alone
	OIDCRedirectURL     string   // default <PublicURL>/auth/callback
	OIDCAllowedDomains  []string // optional email domain allowlist
	OIDCTrustUnverified bool     // accept tokens without email_verified=true (some IdPs omit it)
	OIDCLabel           string   // button text, e.g. "Sign in with Okta"

	// WebhookBaseURL is the public address Git hosts post webhooks to, when it
	// differs from PublicURL (e.g. an ngrok tunnel or a dedicated ingress).
	WebhookBaseURL string
	EnvFile        string // optional .env watched for PRAVAHA_WEBHOOK_BASE_URL
}

type Runner struct {
	ServerURL   string
	Token       string
	StateKey    string
	CAFile      string
	TofuPath    string
	WorkRoot    string
	PluginCache string
	Name        string
}

// DefaultTofuVersion is the OpenTofu release runs are pinned to unless overridden.
const DefaultTofuVersion = "1.13.2"

func LoadServer() (*Server, error) {
	c := &Server{
		DatabaseURL:     secret("PRAVAHA_DATABASE_URL"),
		MasterKey:       secret("PRAVAHA_MASTER_KEY"),
		Listen:          env("PRAVAHA_LISTEN", ":8443"),
		PublicURL:       strings.TrimRight(os.Getenv("PRAVAHA_PUBLIC_URL"), "/"),
		TLSCert:         os.Getenv("PRAVAHA_TLS_CERT"),
		TLSKey:          os.Getenv("PRAVAHA_TLS_KEY"),
		CatalogDir:      env("PRAVAHA_CATALOG_DIR", "../cloud-pravaha-modules/catalog"),
		TofuVersion:     env("PRAVAHA_TOFU_VERSION", DefaultTofuVersion),
		Tenant:          os.Getenv("PRAVAHA_TENANT"),
		CentralURL:      strings.TrimRight(os.Getenv("PRAVAHA_CENTRAL_URL"), "/"),
		CentralIssuer:   strings.TrimRight(env("PRAVAHA_CENTRAL_ISSUER", os.Getenv("PRAVAHA_CENTRAL_URL")), "/"),
		CentralCAFile:   os.Getenv("PRAVAHA_CENTRAL_CA_FILE"),
		CentralClientCA: os.Getenv("PRAVAHA_CENTRAL_CLIENT_CA"),
		CentralJWKSFile: os.Getenv("PRAVAHA_CENTRAL_JWKS_FILE"),

		AllowLocalContracts: os.Getenv("PRAVAHA_ALLOW_LOCAL_CONTRACTS") == "1",

		BucketURL:       os.Getenv("PRAVAHA_BUCKET_URL"),
		BucketAccessKey: secret("PRAVAHA_BUCKET_ACCESS_KEY"),
		BucketSecretKey: secret("PRAVAHA_BUCKET_SECRET_KEY"),
		BucketCreate:    os.Getenv("PRAVAHA_BUCKET_CREATE") == "1",

		TemporalAddress:   os.Getenv("PRAVAHA_TEMPORAL_ADDRESS"),
		TemporalNamespace: env("PRAVAHA_TEMPORAL_NAMESPACE", "default"),

		AssistantAPIKey:    secret("PRAVAHA_ASSISTANT_API_KEY"),
		AssistantBaseURL:   os.Getenv("PRAVAHA_ASSISTANT_BASE_URL"),
		AssistantModel:     env("PRAVAHA_ASSISTANT_MODEL", "claude-opus-5-5"),
		AssistantEffort:    env("PRAVAHA_ASSISTANT_EFFORT", "medium"),
		AssistantDocsDir:   os.Getenv("PRAVAHA_ASSISTANT_DOCS_DIR"),
		AssistantFallbacks: os.Getenv("PRAVAHA_ASSISTANT_FALLBACKS") != "0",
		EnvFile:            absPath(os.Getenv("PRAVAHA_ENV_FILE")),
	}
	var errs []error
	errs = append(errs, common(c.DatabaseURL, c.MasterKey, c.PublicURL, false)...)
	switch c.AssistantEffort {
	case "low", "medium", "high", "xhigh", "max":
	default:
		errs = append(errs, errors.New("PRAVAHA_ASSISTANT_EFFORT must be low, medium, high, xhigh or max"))
	}
	if c.AssistantBaseURL != "" {
		if u, err := url.Parse(c.AssistantBaseURL); err != nil || u.Host == "" || !(u.Scheme == "https" || u.Scheme == "http" && loopbackHost(u.Hostname())) {
			errs = append(errs, errors.New("PRAVAHA_ASSISTANT_BASE_URL must be an https URL (plain http only on loopback, for development)"))
		}
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		errs = append(errs, errors.New("tenant planes always serve TLS: set PRAVAHA_TLS_CERT and PRAVAHA_TLS_KEY"))
	}
	if !slugRe.MatchString(c.Tenant) {
		errs = append(errs, errors.New("PRAVAHA_TENANT must be this plane's tenant slug (as onboarded in the central plane)"))
	}
	if u, err := url.Parse(c.CentralURL); err != nil || u.Host == "" {
		errs = append(errs, errors.New("PRAVAHA_CENTRAL_URL must be the central plane's URL (the assertion issuer)"))
	} else if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname())) {
		errs = append(errs, errors.New("PRAVAHA_CENTRAL_URL must use https (plain http only for a loopback development central)"))
	}
	if c.CentralClientCA == "" {
		errs = append(errs, errors.New("PRAVAHA_CENTRAL_CLIENT_CA is required: user requests are accepted only from central over mTLS"))
	}
	return c, errors.Join(errs...)
}

func LoadCentral() (*Central, error) {
	c := &Central{
		DatabaseURL:  secret("PRAVAHA_DATABASE_URL"),
		MasterKey:    secret("PRAVAHA_MASTER_KEY"),
		Listen:       env("PRAVAHA_LISTEN", ":8443"),
		PublicURL:    strings.TrimRight(os.Getenv("PRAVAHA_PUBLIC_URL"), "/"),
		TLSCert:      os.Getenv("PRAVAHA_TLS_CERT"),
		TLSKey:       os.Getenv("PRAVAHA_TLS_KEY"),
		InsecureHTTP: os.Getenv("PRAVAHA_INSECURE_HTTP") == "1",
		WebDir:       os.Getenv("PRAVAHA_WEB_DIR"),
		ClientCert:   os.Getenv("PRAVAHA_CLIENT_CERT"),
		ClientKey:    os.Getenv("PRAVAHA_CLIENT_KEY"),

		OIDCIssuer:          strings.TrimRight(os.Getenv("PRAVAHA_OIDC_ISSUER"), "/"),
		OIDCClientID:        os.Getenv("PRAVAHA_OIDC_CLIENT_ID"),
		OIDCClientSecret:    secret("PRAVAHA_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:     os.Getenv("PRAVAHA_OIDC_REDIRECT_URL"),
		OIDCTrustUnverified: os.Getenv("PRAVAHA_OIDC_TRUST_UNVERIFIED_EMAIL") == "1",
		OIDCLabel:           env("PRAVAHA_OIDC_LABEL", "Sign in with SSO"),
		WebhookBaseURL:      strings.TrimRight(os.Getenv("PRAVAHA_WEBHOOK_BASE_URL"), "/"),
		EnvFile:             absPath(os.Getenv("PRAVAHA_ENV_FILE")),
	}
	for _, d := range strings.Split(os.Getenv("PRAVAHA_OIDC_ALLOWED_DOMAINS"), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.OIDCAllowedDomains = append(c.OIDCAllowedDomains, d)
		}
	}
	errs := common(c.DatabaseURL, c.MasterKey, c.PublicURL, c.InsecureHTTP)
	if c.InsecureHTTP {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil || !loopbackHost(host) {
			errs = append(errs, errors.New("PRAVAHA_INSECURE_HTTP=1 is only allowed with a loopback PRAVAHA_LISTEN such as 127.0.0.1:8080"))
		}
	} else if c.TLSCert == "" || c.TLSKey == "" {
		errs = append(errs, errors.New("TLS is required: set PRAVAHA_TLS_CERT and PRAVAHA_TLS_KEY"))
	}
	if c.ClientCert == "" || c.ClientKey == "" {
		errs = append(errs, errors.New("PRAVAHA_CLIENT_CERT and PRAVAHA_CLIENT_KEY are required: central calls tenant planes over mTLS"))
	}
	if c.WebhookBaseURL != "" {
		if u, err := url.Parse(c.WebhookBaseURL); err != nil || u.Host == "" || u.Path != "" || u.Scheme != "https" {
			errs = append(errs, errors.New("PRAVAHA_WEBHOOK_BASE_URL must be an https origin, e.g. https://hooks.example.com"))
		}
	}
	if c.OIDCIssuer != "" {
		if u, err := url.Parse(c.OIDCIssuer); err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
			errs = append(errs, errors.New("PRAVAHA_OIDC_ISSUER must be an https URL"))
		}
		if c.OIDCClientID == "" {
			errs = append(errs, errors.New("PRAVAHA_OIDC_CLIENT_ID is required with PRAVAHA_OIDC_ISSUER"))
		}
		if c.OIDCRedirectURL == "" {
			c.OIDCRedirectURL = c.PublicURL + "/auth/callback"
		}
	}
	return c, errors.Join(errs...)
}

var slugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

func common(db, key, public string, insecure bool) []error {
	var errs []error
	if db == "" {
		errs = append(errs, errors.New("PRAVAHA_DATABASE_URL is required"))
	}
	if key == "" {
		errs = append(errs, errors.New("PRAVAHA_MASTER_KEY is required (openssl rand -base64 32)"))
	}
	u, err := url.Parse(public)
	if public == "" || err != nil || u.Host == "" {
		errs = append(errs, errors.New("PRAVAHA_PUBLIC_URL is required"))
	} else if u.Scheme != "https" && !(insecure && u.Scheme == "http" && loopbackHost(u.Hostname())) {
		errs = append(errs, errors.New("PRAVAHA_PUBLIC_URL must use https"))
	}
	return errs
}

func LoadRunner() (*Runner, error) {
	c := &Runner{
		ServerURL:   strings.TrimRight(os.Getenv("PRAVAHA_SERVER_URL"), "/"),
		Token:       secret("PRAVAHA_RUNNER_TOKEN"),
		StateKey:    secret("PRAVAHA_STATE_KEY"),
		CAFile:      os.Getenv("PRAVAHA_CA_FILE"),
		TofuPath:    env("PRAVAHA_TOFU_PATH", "tofu"),
		WorkRoot:    os.Getenv("PRAVAHA_WORK_DIR"),
		PluginCache: os.Getenv("PRAVAHA_PLUGIN_CACHE_DIR"),
		Name:        env("PRAVAHA_RUNNER_NAME", hostname()),
	}
	var errs []error
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Host == "" {
		errs = append(errs, errors.New("PRAVAHA_SERVER_URL is required"))
	} else if u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()) && os.Getenv("PRAVAHA_INSECURE_HTTP") == "1") {
		errs = append(errs, errors.New("PRAVAHA_SERVER_URL must use https"))
	}
	if !strings.HasPrefix(c.Token, "pvh_r_") {
		errs = append(errs, errors.New("PRAVAHA_RUNNER_TOKEN must be a runner token (pvh_r_...)"))
	}
	if len(c.StateKey) < 32 {
		errs = append(errs, errors.New("PRAVAHA_STATE_KEY must be at least 32 characters; every runner in a pool must share it"))
	}
	return c, errors.Join(errs...)
}

// secret reads NAME, or the file named by NAME_FILE (for Kubernetes/Docker secrets).
func secret(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s_FILE: %v\n", name, err)
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(name)
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func hostname() string {
	h, _ := os.Hostname()
	return h
}

func absPath(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}
