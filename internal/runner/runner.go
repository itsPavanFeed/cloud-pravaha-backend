// Package runner is the agent that executes OpenTofu.
//
// It only makes outbound HTTPS requests to the control plane, so it can sit in
// a private subnet next to the cloud accounts it manages. Each run gets a fresh
// 0700 temporary directory and a minimal environment, and the directory is
// deleted when the run ends.
package runner

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/api"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/bundlecache"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/config"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/depcheck"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/policy"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/redact"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/release"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/secure"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
)

const (
	planTimeout  = 30 * time.Minute
	applyTimeout = 2 * time.Hour
	planFile     = "plan.bin"
)

type Runner struct {
	cfg      *config.Runner
	http     *http.Client
	log      *slog.Logger
	caPEM    string
	pinned   *catalog.Catalog // a locally pinned catalog overrides the one in jobs
	tofuPath string
	initMu   sync.Mutex         // tofu init shares the provider plugin cache; inits run one at a time
	bundles  *bundlecache.Cache // module release bundles, by checksum
}

type jobKey struct{}

// fetchBundle downloads a bundle from the tenant plane with the run's token
// (the job travels in the context; the cache verifies the checksum).
func (r *Runner) fetchBundle(ctx context.Context, sha string) ([]byte, error) {
	j, _ := ctx.Value(jobKey{}).(*job)
	if j == nil {
		return nil, errors.New("no run to fetch the bundle for")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.ServerURL+"/api/v1/agent/runs/"+j.RunID+"/bundles/"+sha, nil)
	req.Header.Set("Authorization", "Bearer "+j.RunToken)
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading the module bundle: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// extractModules writes the run's module packages from the release bundle
// and verifies each one against the checksum in the generated config.
func (j *job) extractModules(ctx context.Context) error {
	b := j.Bundle
	j.logs.Printf("==> modules from release bundle %s (%d packages)\n", b.SHA256[:12], len(b.Packages))
	data, err := j.r.bundles.Get(context.WithValue(ctx, jobKey{}, j), b.SHA256)
	if err != nil {
		return fmt.Errorf("module bundle: %w", err)
	}
	got := map[string]map[string][]byte{}
	for dir := range b.Packages {
		if !strings.HasPrefix(dir, spec.VendorDir+"/") || strings.Contains(dir, "..") || strings.Count(dir, "/") != 4 {
			return fmt.Errorf("job names an invalid module package %q", dir)
		}
		got[dir] = map[string][]byte{}
	}
	owner := func(name string) string {
		if parts := strings.SplitN(name, "/", 6); len(parts) == 6 {
			return strings.Join(parts[:5], "/")
		}
		return ""
	}
	_, err = release.Unpack(data, b.SHA256, func(name string) bool { _, ok := got[owner(name)]; return ok },
		func(name string, content []byte) error {
			dir := owner(name)
			got[dir][strings.TrimPrefix(name, dir+"/")] = content
			p := filepath.Join(j.dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				return err
			}
			return os.WriteFile(p, content, 0o600)
		})
	if err != nil {
		return fmt.Errorf("module bundle: %w", err)
	}
	for dir, want := range b.Packages {
		if sum := release.PackageSum(got[dir]); sum != want {
			return fmt.Errorf("module package %s does not match its checksum (got %s, want %s)", dir, sum[:12], want[:12])
		}
	}
	j.logs.Printf("    every package verified by checksum; no module is downloaded from the internet\n")
	return nil
}

func New(cfg *config.Runner, log *slog.Logger) (*Runner, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	r := &Runner{cfg: cfg, log: log}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("PRAVAHA_CA_FILE contains no certificates")
		}
		tlsCfg.RootCAs = pool
		r.caPEM = string(pem)
	}
	r.http = &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment}}
	p, err := exec.LookPath(cfg.TofuPath)
	if err != nil {
		return nil, fmt.Errorf("OpenTofu binary not found: %w", err)
	}
	r.tofuPath, _ = filepath.Abs(p)
	if dir := os.Getenv("PRAVAHA_CATALOG_DIR"); dir != "" {
		if r.pinned, err = catalog.Load(dir); err != nil {
			return nil, fmt.Errorf("pinned catalog: %w", err)
		}
		log.Info("using locally pinned catalog; catalogs sent by the control plane are ignored", "dir", dir)
	}
	if cfg.WorkRoot != "" {
		if err := os.MkdirAll(cfg.WorkRoot, 0o700); err != nil {
			return nil, err
		}
	}
	dir := cfg.BundleCacheDir
	if dir == "" {
		if d, err := os.UserCacheDir(); err == nil {
			dir = filepath.Join(d, "pravaha", "runner-bundles")
		}
	}
	if r.bundles, err = bundlecache.New(r.fetchBundle, dir, 512<<20, cfg.BundleCacheDisk); err != nil {
		log.Warn("bundle disk cache unavailable; caching in memory only", "dir", dir, "err", err)
		r.bundles, _ = bundlecache.New(r.fetchBundle, "", 512<<20, 0)
	}
	return r, nil
}

// Run polls for work until ctx is cancelled, executing up to Concurrency runs
// at once. Each run gets its own work directory and TMPDIR, removed when it
// ends, so concurrent runs never share files. Scale further with more runners.
func (r *Runner) Run(ctx context.Context) error {
	n := max(r.cfg.Concurrency, 1)
	r.log.Info("runner started", "server", r.cfg.ServerURL, "tofu", r.tofuPath, "concurrency", n)
	slots := make(chan struct{}, n)
	var wg sync.WaitGroup
	defer wg.Wait() // let running jobs finish reporting
	backoff := time.Second
	for ctx.Err() == nil {
		select { // claim only when a slot is free
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		job, err := r.claim(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			<-slots
			r.log.Warn("claim failed", "err", err, "retry_in", backoff)
			sleep(ctx, backoff)
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		if job == nil {
			<-slots
			continue
		}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			r.execute(ctx, job)
		}()
	}
	return nil
}

func (r *Runner) claim(ctx context.Context) (*api.Job, error) {
	cctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(cctx, http.MethodPost, r.cfg.ServerURL+"/api/v1/agent/claim", nil)
	req.Header.Set("Authorization", "Bearer "+r.cfg.Token)
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, nil
	case http.StatusOK:
		var j api.Job
		if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
			return nil, err
		}
		return &j, nil
	default:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("control plane returned %s: %s", resp.Status, b)
	}
}

// job holds per-run state.
type job struct {
	*api.Job
	r       *Runner
	dir     string
	tmp     string // short private TMPDIR: plugin sockets live here and macOS caps socket paths at 104 bytes
	red     *redact.Redactor
	logs    *logSink
	env     []string
	catalog *catalog.Catalog
}

func (r *Runner) execute(ctx context.Context, j *api.Job) {
	log := r.log.With("run", j.RunID, "stack", j.Stack, "phase", j.Phase)
	log.Info("run claimed")
	passphrase := secure.Derive([]byte(r.cfg.StateKey), "pravaha-state:"+j.StackID)
	rj := &job{Job: j, r: r, red: redact.New(j.RunToken, j.OIDCToken, j.VaultToken, passphrase, r.cfg.StateKey, r.cfg.Token)}
	rj.logs = newLogSink(ctx, r, j)
	defer rj.logs.Close()

	err := rj.run(ctx, passphrase)
	status := "applied"
	msg := ""
	if err != nil {
		status, msg = "failed", rj.red.String(err.Error())
		rj.logs.Write([]byte("\nERROR: " + msg + "\n"))
		log.Warn("run failed", "err", msg)
	} else if j.Phase == "plan" {
		log.Info("plan uploaded")
		return // the control plane moved the run to planned / no_changes / policy_failed
	} else {
		log.Info("apply finished")
	}
	rj.logs.Flush()
	if err := rj.call(ctx, http.MethodPost, "/finish", map[string]string{"status": status, "error": msg}, nil); err != nil {
		log.Error("reporting run result failed", "err", err)
	}
}

func (j *job) run(ctx context.Context, passphrase string) (err error) {
	j.dir, err = os.MkdirTemp(j.r.cfg.WorkRoot, "pravaha-run-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(j.dir)
	if err := os.Chmod(j.dir, 0o700); err != nil {
		return err
	}
	if j.tmp, err = os.MkdirTemp("", "pvh-"); err != nil {
		return err
	}
	defer os.RemoveAll(j.tmp)

	if j.r.pinned != nil {
		j.catalog = j.r.pinned
	} else if j.catalog, err = catalog.New(j.Catalog.Modules, j.Catalog.Providers); err != nil {
		return fmt.Errorf("job catalog is invalid: %w", err)
	}
	// The runner re-derives the allowed providers itself rather than trusting the job list.
	for _, p := range j.Providers {
		if _, ok := j.catalog.Provider(p); !ok {
			return fmt.Errorf("job asks for provider %s, which the catalog does not allow", p)
		}
	}
	if err := j.writeFiles(); err != nil {
		return err
	}
	if j.Bundle != nil {
		if err := j.extractModules(ctx); err != nil {
			return err
		}
	}
	if err := j.buildEnv(passphrase); err != nil {
		return err
	}
	if err := j.checkTofuVersion(ctx); err != nil {
		return err
	}

	timeout := planTimeout
	if j.Phase == "apply" {
		timeout = applyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if j.Phase == "apply" {
		if err := j.fetchPlan(ctx); err != nil {
			return err
		}
	}
	j.logs.Printf("==> tofu init (OpenTofu %s, %d allowlisted providers)\n", j.TofuVersion, len(j.Providers))
	// init is idempotent; retry transient registry and network failures.
	for attempt := 1; ; attempt++ {
		j.r.initMu.Lock()
		err := j.tofu(ctx, "init", "-input=false", "-no-color")
		j.r.initMu.Unlock()
		if err == nil {
			break
		}
		if attempt == 3 || ctx.Err() != nil {
			return fmt.Errorf("tofu init failed: %w", err)
		}
		j.logs.Printf("==> tofu init failed (attempt %d of 3); retrying in %ds\n", attempt, attempt*5)
		sleep(ctx, time.Duration(attempt*5)*time.Second)
	}
	j.logs.Printf("==> verifying downloaded modules and providers against the catalog\n")
	if err := depcheck.Check(j.dir, j.catalog); err != nil {
		return fmt.Errorf("dependency check failed:\n%w", err)
	}
	j.logs.Printf("    all modules are pinned public registry modules; all providers are allowlisted\n")

	if j.Phase == "plan" {
		return j.plan(ctx)
	}
	j.logs.Printf("==> tofu apply (saved plan %s)\n", j.PlanSHA256[:12])
	if err := j.tofu(ctx, "apply", "-input=false", "-no-color", "-lock-timeout=60s", planFile); err != nil {
		return fmt.Errorf("tofu apply failed: %w", err)
	}
	return nil
}

func (j *job) writeFiles() error {
	if err := os.MkdirAll(filepath.Join(j.dir, ".pravaha", "home"), 0o700); err != nil {
		return err
	}
	for name, data := range j.Files {
		// Only the files the generator produces: main.tf and .pravaha/*.
		if name != spec.ConfigFile && !(strings.HasPrefix(name, ".pravaha/") && !strings.Contains(name, "..") && strings.Count(name, "/") == 1) {
			return fmt.Errorf("job contains unexpected file %q", name)
		}
		if err := os.WriteFile(filepath.Join(j.dir, name), data, 0o600); err != nil {
			return err
		}
	}
	if j.OIDCToken != "" {
		if err := os.WriteFile(filepath.Join(j.dir, spec.TokenFile), []byte(j.OIDCToken), 0o600); err != nil {
			return err
		}
	}
	if j.VaultToken != "" { // read by the vault provider's JWT login (file() in the generated config)
		if err := os.WriteFile(filepath.Join(j.dir, spec.VaultTokenFile), []byte(j.VaultToken), 0o600); err != nil {
			return err
		}
	}
	for name, data := range j.CloudFiles {
		if name != spec.GCPExternalFile {
			return fmt.Errorf("job contains unexpected credential file %q", name)
		}
		if err := os.WriteFile(filepath.Join(j.dir, name), data, 0o600); err != nil {
			return err
		}
	}
	// Provider installation is restricted to the allowlist, so even a module that
	// slipped past validation could not install an arbitrary provider.
	var inc []string
	for _, p := range j.Providers {
		inc = append(inc, fmt.Sprintf("%q", catalog.Registry+"/"+p))
	}
	cli := "disable_checkpoint = true\n"
	if len(inc) > 0 {
		cli += "provider_installation {\n  direct {\n    include = [" + strings.Join(inc, ", ") + "]\n  }\n}\n"
	} else {
		cli += "provider_installation {\n  direct {\n    exclude = [\"*/*/*\"]\n  }\n}\n"
	}
	return os.WriteFile(filepath.Join(j.dir, ".pravaha", "cli.tfrc"), []byte(cli), 0o600)
}

// buildEnv gives OpenTofu a minimal environment: no inherited cloud
// credentials, a private HOME, the run-scoped state token and enforced state
// and plan encryption.
func (j *job) buildEnv(passphrase string) error {
	enc := fmt.Sprintf(`key_provider "pbkdf2" "pravaha" {
  passphrase = %q
}
method "aes_gcm" "pravaha" {
  keys = key_provider.pbkdf2.pravaha
}
state {
  method   = method.aes_gcm.pravaha
  enforced = true
}
plan {
  method   = method.aes_gcm.pravaha
  enforced = true
}
`, passphrase)
	j.env = []string{
		"PATH=" + filepath.Dir(j.r.tofuPath) + ":/usr/bin:/bin",
		"HOME=" + filepath.Join(j.dir, ".pravaha", "home"),
		"TMPDIR=" + j.tmp,
		"TF_IN_AUTOMATION=1",
		"TF_INPUT=0",
		"CHECKPOINT_DISABLE=1",
		"TF_CLI_CONFIG_FILE=" + filepath.Join(j.dir, ".pravaha", "cli.tfrc"),
		"TF_HTTP_ADDRESS=" + j.r.cfg.ServerURL + "/state/v1/" + j.StackID,
		"TF_HTTP_LOCK_ADDRESS=" + j.r.cfg.ServerURL + "/state/v1/" + j.StackID,
		"TF_HTTP_UNLOCK_ADDRESS=" + j.r.cfg.ServerURL + "/state/v1/" + j.StackID,
		"TF_HTTP_USERNAME=run",
		"TF_HTTP_PASSWORD=" + j.RunToken,
		"TF_ENCRYPTION=" + enc,
	}
	if j.r.caPEM != "" {
		j.env = append(j.env, "TF_HTTP_CLIENT_CA_CERTIFICATE_PEM="+j.r.caPEM)
	}
	// Phase identity from the control plane: only allowlisted variables, so a
	// compromised control plane cannot inject OpenTofu options (TF_CLI_ARGS, ...).
	for k, v := range j.CloudEnv {
		if !spec.PhaseEnvAllowed[k] || strings.ContainsAny(v, "\x00\n") {
			return fmt.Errorf("job sets environment variable %q, which runners do not accept", k)
		}
		if strings.HasSuffix(k, "_FILE") {
			if v != spec.TokenFile {
				return fmt.Errorf("job points %s outside the run directory", k)
			}
			v = filepath.Join(j.dir, v)
		}
		j.env = append(j.env, k+"="+v)
	}
	if j.r.cfg.PluginCache != "" {
		// Safe to share: init verifies every provider against the lock file hashes.
		j.env = append(j.env, "TF_PLUGIN_CACHE_DIR="+j.r.cfg.PluginCache)
	}
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"} {
		if v := os.Getenv(k); v != "" {
			j.env = append(j.env, k+"="+v)
		}
	}
	return nil
}

func (j *job) checkTofuVersion(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, j.r.tofuPath, "version", "-json")
	cmd.Dir, cmd.Env = j.dir, j.env
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("running tofu version: %w", err)
	}
	var v struct {
		Version string `json:"terraform_version"`
	}
	json.Unmarshal(out, &v)
	if v.Version != j.TofuVersion {
		return fmt.Errorf("runner has OpenTofu %s but runs are pinned to %s", v.Version, j.TofuVersion)
	}
	return nil
}

func (j *job) tofu(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, j.r.tofuPath, args...)
	cmd.Dir, cmd.Env = j.dir, j.env
	w := &redactWriter{red: j.red, out: j.logs}
	cmd.Stdout, cmd.Stderr = w, w
	cmd.WaitDelay = 30 * time.Second
	err := cmd.Run()
	w.Flush()
	return err
}

func (j *job) plan(ctx context.Context) error {
	args := []string{"plan", "-input=false", "-no-color", "-lock-timeout=60s", "-out=" + planFile}
	switch j.Operation {
	case "destroy":
		args = append(args, "-destroy")
	case "drift":
		args = append(args, "-refresh-only") // compare real infrastructure with state; never changes anything
	}
	j.logs.Printf("==> tofu %s\n", strings.Join(args, " "))
	if err := j.tofu(ctx, args...); err != nil {
		return fmt.Errorf("tofu plan failed: %w", err)
	}
	cmd := exec.CommandContext(ctx, j.r.tofuPath, "show", "-json", planFile)
	cmd.Dir, cmd.Env = j.dir, j.env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("tofu show failed: %s", j.red.String(stderr.String()))
	}
	summary, err := Summarize(out)
	if err != nil {
		return err
	}
	plan, err := os.ReadFile(filepath.Join(j.dir, planFile))
	if err != nil {
		return err
	}
	if j.Operation == "drift" {
		j.logs.Printf("==> drift check: %d resource(s) changed outside OpenTofu\n", len(summary.Drift))
	} else {
		j.logs.Printf("==> plan: %d to add, %d to change, %d to destroy, %d to replace; uploading for policy checks\n", summary.Add, summary.Change, summary.Destroy, summary.Replace)
	}
	j.logs.Flush()
	var res struct{ Status string }
	if err := j.call(ctx, http.MethodPost, "/plan", map[string]any{"summary": summary, "plan": plan, "sha256": secure.SHA256Hex(plan)}, &res); err != nil {
		return fmt.Errorf("uploading plan: %w", err)
	}
	j.logs.Printf("==> control plane result: %s\n", res.Status)
	return nil
}

func (j *job) fetchPlan(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, j.r.cfg.ServerURL+"/api/v1/agent/runs/"+j.RunID+"/plan", nil)
	req.Header.Set("Authorization", "Bearer "+j.RunToken)
	resp, err := j.r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetching saved plan: %s", resp.Status)
	}
	plan, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if got := secure.SHA256Hex(plan); got != j.PlanSHA256 {
		return fmt.Errorf("saved plan checksum %s does not match the approved plan %s", got, j.PlanSHA256)
	}
	j.logs.Printf("==> saved plan verified (sha256 %s)\n", j.PlanSHA256)
	return os.WriteFile(filepath.Join(j.dir, planFile), plan, 0o600)
}

// call makes a run-token request to /api/v1/agent/runs/{id}{path}.
func (j *job) call(ctx context.Context, method, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(context.WithoutCancel(ctx), method, j.r.cfg.ServerURL+"/api/v1/agent/runs/"+j.RunID+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+j.RunToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := j.r.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s: %s", resp.Status, msg)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ---- plan summary ----

type resourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Mode    string `json:"mode"`
	Change  struct {
		Actions        []string `json:"actions"`
		Importing      any      `json:"importing"`
		After          any      `json:"after"`
		AfterSensitive any      `json:"after_sensitive"`
		AfterUnknown   any      `json:"after_unknown"`
	} `json:"change"`
}

type planJSON struct {
	ResourceDrift   []resourceChange `json:"resource_drift"`
	ResourceChanges []struct {
		Address string `json:"address"`
		Type    string `json:"type"`
		Mode    string `json:"mode"`
		Change  struct {
			Actions        []string `json:"actions"`
			Importing      any      `json:"importing"`
			After          any      `json:"after"`
			AfterSensitive any      `json:"after_sensitive"`
			AfterUnknown   any      `json:"after_unknown"`
		} `json:"change"`
	} `json:"resource_changes"`
	OutputChanges map[string]any `json:"output_changes"`
}

// Summarize turns `tofu show -json` into the policy summary. Sensitive and
// unknown values are removed before anything leaves the runner.
func Summarize(b []byte) (policy.Summary, error) {
	var p planJSON
	if err := json.Unmarshal(b, &p); err != nil {
		return policy.Summary{}, fmt.Errorf("parsing plan JSON: %w", err)
	}
	s := policy.Summary{Resources: []policy.ResourceChange{}}
	for _, rc := range p.ResourceChanges {
		a := rc.Change.Actions
		importing := rc.Change.Importing != nil
		if importing {
			s.Imports++
			if len(a) == 1 && a[0] == "no-op" {
				a = []string{"import"}
			}
		}
		if rc.Mode == "data" || len(a) == 0 || a[0] == "no-op" || a[0] == "read" {
			continue
		}
		switch {
		case len(a) == 2:
			s.Replace++
		case a[0] == "create":
			s.Add++
		case a[0] == "update":
			s.Change++
		case a[0] == "delete":
			s.Destroy++
		}
		ch := policy.ResourceChange{Address: rc.Address, Type: rc.Type, Actions: a, Importing: importing}
		if m, ok := scrub(rc.Change.After, rc.Change.AfterSensitive, rc.Change.AfterUnknown).(map[string]any); ok {
			if enc, _ := json.Marshal(m); len(enc) <= 8<<10 {
				ch.After = m
			}
		}
		s.Resources = append(s.Resources, ch)
	}
	for name := range p.OutputChanges {
		s.Outputs = append(s.Outputs, name)
	}
	for _, rd := range p.ResourceDrift {
		if rd.Mode == "data" || len(rd.Change.Actions) == 0 || rd.Change.Actions[0] == "no-op" {
			continue
		}
		s.Drift = append(s.Drift, policy.ResourceChange{Address: rd.Address, Type: rd.Type, Actions: rd.Change.Actions})
	}
	return s, nil
}

// scrub drops any value marked sensitive or unknown, recursively.
func scrub(v, sens, unk any) any {
	if b, ok := sens.(bool); ok && b {
		return nil
	}
	if b, ok := unk.(bool); ok && b {
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		sm, _ := sens.(map[string]any)
		um, _ := unk.(map[string]any)
		out := map[string]any{}
		for k, x := range t {
			if y := scrub(x, sm[k], um[k]); y != nil {
				out[k] = y
			}
		}
		return out
	case []any:
		sl, _ := sens.([]any)
		ul, _ := unk.([]any)
		out := make([]any, 0, len(t))
		for i, x := range t {
			var si, ui any
			if i < len(sl) {
				si = sl[i]
			}
			if i < len(ul) {
				ui = ul[i]
			}
			out = append(out, scrub(x, si, ui))
		}
		return out
	}
	return v
}

// ---- log streaming ----

// logSink batches log output and ships it to the control plane every second.
type logSink struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	ctx  context.Context
	r    *Runner
	job  *api.Job
	done chan struct{}
	wg   sync.WaitGroup
}

func newLogSink(ctx context.Context, r *Runner, j *api.Job) *logSink {
	l := &logSink{ctx: ctx, r: r, job: j, done: make(chan struct{})}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-l.done:
				return
			case <-t.C:
				l.Flush()
			}
		}
	}()
	return l
}

func (l *logSink) Write(p []byte) (int, error) {
	l.mu.Lock()
	l.buf.Write(p)
	full := l.buf.Len() > 64<<10
	l.mu.Unlock()
	if full {
		l.Flush()
	}
	return len(p), nil
}

func (l *logSink) Printf(format string, a ...any) { fmt.Fprintf(l, format, a...) }

func (l *logSink) Flush() {
	l.mu.Lock()
	if l.buf.Len() == 0 {
		l.mu.Unlock()
		return
	}
	chunk := append([]byte(nil), l.buf.Bytes()...)
	l.buf.Reset()
	l.mu.Unlock()
	req, _ := http.NewRequestWithContext(context.WithoutCancel(l.ctx), http.MethodPost, l.r.cfg.ServerURL+"/api/v1/agent/runs/"+l.job.RunID+"/logs", bytes.NewReader(chunk))
	req.Header.Set("Authorization", "Bearer "+l.job.RunToken)
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	if resp, err := l.r.http.Do(req); err == nil {
		resp.Body.Close()
	} else {
		l.r.log.Warn("shipping logs failed", "err", err)
	}
}

func (l *logSink) Close() {
	close(l.done)
	l.wg.Wait()
	l.Flush()
}

// redactWriter redacts complete lines, so a secret is never split across chunks.
type redactWriter struct {
	red     *redact.Redactor
	out     io.Writer
	mu      sync.Mutex
	partial []byte
}

func (w *redactWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.partial = append(w.partial, p...)
	if i := bytes.LastIndexByte(w.partial, '\n'); i >= 0 {
		w.out.Write([]byte(w.red.String(string(w.partial[:i+1]))))
		w.partial = append([]byte(nil), w.partial[i+1:]...)
	}
	if len(w.partial) > 64<<10 {
		w.out.Write([]byte(w.red.String(string(w.partial))))
		w.partial = nil
	}
	return len(p), nil
}

func (w *redactWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.partial) > 0 {
		w.out.Write([]byte(w.red.String(string(w.partial))))
		w.partial = nil
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
