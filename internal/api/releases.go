package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/catalog"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/contracts"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/release"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/spec"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// Releases: the platform builds what the tenant keeps in Git (the modules
// repository with its kinds and tenant defaults, and the policies repository)
// into verified, immutable releases, and deploys them on request. A deployed
// module release carries the catalog, this tenant's defaults and every module
// package vendored, so after a deploy nothing reads the repository or the
// public registry again until the next build.

// ReleaseSource is where one kind of release is built from.
type ReleaseSource struct {
	Provider    string `json:"provider"` // github | gitlab | local
	Repo        string `json:"repo"`
	Branch      string `json:"branch"`
	Path        string `json:"path"` // folder holding catalog/ + tenants/ (modules) or global/ + tenants/ (policies)
	APIURL      string `json:"api_url,omitempty"`
	Auth        string `json:"auth,omitempty"` // token | github_app
	PollSeconds int    `json:"poll_seconds"`
	Enabled     bool   `json:"enabled"`   // build new commits and pull requests automatically (webhooks, or polling the branch)
	Approvals   int    `json:"approvals"` // DevOps approvals needed to activate a release (0-5)
}

func (c ReleaseSource) gitConfig() contracts.Config {
	return contracts.Config{Provider: c.Provider, Repo: c.Repo, Branch: c.Branch, Path: c.Path, APIURL: c.APIURL, Auth: c.Auth, PollSeconds: c.PollSeconds, Enabled: c.Enabled}
}

func releaseKind(w http.ResponseWriter, r *http.Request) (string, bool) {
	k := r.PathValue("kind")
	if k != release.Modules && k != release.Policies {
		writeErr(w, http.StatusNotFound, "unknown release kind (modules or policies)")
		return "", false
	}
	return k, true
}

func sourceKey(kind string) string { return "release_source_" + kind }
func tokenKey(kind string) string  { return "release_token_" + kind }
func tokenAADFor(kind string) []byte {
	return []byte("release-token-" + kind)
}

func (s *Server) releaseSource(ctx context.Context, kind string) (*ReleaseSource, bool) {
	var c ReleaseSource
	if ok, err := s.store.Setting(ctx, sourceKey(kind), &c); err != nil || !ok {
		return nil, false
	}
	return &c, true
}

func (s *Server) getReleaseSource(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok {
		return
	}
	cfg, _ := s.releaseSource(r.Context(), kind)
	var tok map[string]string
	hasToken, _ := s.store.Setting(r.Context(), tokenKey(kind), &tok)
	writeJSON(w, 200, map[string]any{"config": cfg, "token_set": hasToken})
}

func (s *Server) putReleaseSource(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok || !tenantAdmin(w, r) { // only tenant admins decide where releases come from and how many approvals they need
		return
	}
	var c ReleaseSource
	if !decode(w, r, &c) {
		return
	}
	gc := c.gitConfig()
	if c.Approvals < 0 || c.Approvals > 5 {
		writeErr(w, 422, "invalid "+kind+" repository", "approvals must be between 0 and 5")
		return
	}
	if err := gc.Validate(s.cfg.AllowLocalContracts); err != nil {
		writeErr(w, 422, "invalid "+kind+" repository", errLines(err)...)
		return
	}
	if _, ok := s.githubAppConfig(r.Context()); c.Auth == "github_app" && !ok {
		writeErr(w, 422, "invalid "+kind+" repository", "configure the GitHub App under Integrations first")
		return
	}
	if err := s.store.PutSetting(r.Context(), sourceKey(kind), c, user(r).Subject); err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "release.source", "releases/"+kind, "", c)
	writeJSON(w, 200, c)
}

func (s *Server) putReleaseToken(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok || !tenantAdmin(w, r) {
		return
	}
	var b struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Token) < 8 || len(b.Token) > 512 || strings.ContainsAny(b.Token, " \n\r\t") {
		writeErr(w, 422, "token must be 8-512 characters without whitespace")
		return
	}
	sealed, err := s.sealer.Seal([]byte(b.Token), tokenAADFor(kind))
	if err == nil {
		err = s.store.PutSetting(r.Context(), tokenKey(kind), map[string]string{"sealed": base64.StdEncoding.EncodeToString(sealed)}, user(r).Subject)
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	s.audit(r.Context(), user(r).Actor(), "release.token", "releases/"+kind, "", map[string]bool{"set": true})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) releaseGit(ctx context.Context, kind string, c *ReleaseSource) (contracts.Source, error) {
	token := ""
	if c.Auth == "github_app" {
		var err error
		if token, err = s.githubInstallationToken(ctx, c.Repo); err != nil {
			return nil, err
		}
	} else {
		var t map[string]string
		if ok, _ := s.store.Setting(ctx, tokenKey(kind), &t); ok {
			if sealed, err := base64.StdEncoding.DecodeString(t["sealed"]); err == nil {
				if pt, err := s.sealer.Open(sealed, tokenAADFor(kind)); err == nil {
					token = string(pt)
				}
			}
		}
	}
	return contracts.New(c.gitConfig(), token, nil)
}

func (s *Server) listReleases(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok {
		return
	}
	rels, err := s.store.ListReleases(r.Context(), kind, limit(r, 20, 100))
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	resp := map[string]any{"releases": rels}
	if kind == release.Modules {
		if p := s.plat(); p.release == nil {
			resp["bundled"] = map[string]any{"kinds": len(p.cat.Modules), "defaults": len(p.defaults.Kinds)}
		}
	}
	writeJSON(w, 200, resp)
}

func (s *Server) getRelease(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok {
		return
	}
	rel, err := s.store.GetRelease(r.Context(), r.PathValue("id"))
	if err == nil && rel.Kind != kind {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	writeJSON(w, 200, rel)
}

func (s *Server) buildReleaseNow(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok || !releaseEditor(w, r) {
		return
	}
	rel, err := s.startBranchBuild(r.Context(), kind, user(r).Actor())
	switch {
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, "this commit is already built")
	case err != nil:
		writeErr(w, http.StatusBadGateway, err.Error())
	default:
		writeJSON(w, 202, rel)
	}
}

func (s *Server) bundleCacheStats(w http.ResponseWriter, r *http.Request) {
	if !tenantAdmin(w, r) {
		return
	}
	writeJSON(w, 200, s.bundles.Stats())
}

// ---- building ----

var buildMu sync.Mutex // builds run one at a time per replica: they download modules and are heavy

// buildReq is one build: from the repository at a commit, or from files
// assembled in the console (a change not committed yet).
type buildReq struct {
	kind, actor, rev string
	origin           store.ReleaseOrigin
	files            map[string][]byte // nil: read the repository at rev
	// after runs once every check passed, before the release is marked ready:
	// console changes are committed here, so only a change that builds is committed.
	after func(ctx context.Context, rel *store.Release) error
}

// startBranchBuild builds the source branch's current commit.
func (s *Server) startBranchBuild(ctx context.Context, kind, actor string) (*store.Release, error) {
	c, src, err := s.releaseRepo(ctx, kind)
	if err != nil {
		return nil, err
	}
	rev, err := src.Revision(ctx)
	if err != nil {
		return nil, err
	}
	return s.startBuild(ctx, c, src, buildReq{kind: kind, actor: actor, rev: rev, origin: store.ReleaseOrigin{Origin: "branch", Ref: c.Branch, Title: "branch " + c.Branch}})
}

func (s *Server) releaseRepo(ctx context.Context, kind string) (*ReleaseSource, contracts.Source, error) {
	c, ok := s.releaseSource(ctx, kind)
	if !ok {
		return nil, nil, fmt.Errorf("no %s repository is configured", kind)
	}
	src, err := s.releaseGit(ctx, kind, c)
	return c, src, err
}

// startBuild records a build and runs it in the background.
func (s *Server) startBuild(ctx context.Context, c *ReleaseSource, src contracts.Source, b buildReq) (*store.Release, error) {
	rel, err := s.store.StartRelease(ctx, b.kind, b.rev, b.actor, b.origin)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, b.actor, "release.build", "releases/"+b.kind+"/"+strconv.Itoa(rel.Number), "",
		map[string]any{"revision": b.rev, "repo": c.Repo, "origin": b.origin.Origin, "pr": b.origin.PRNumber})
	s.releaseStatus(ctx, c, rel, "pending", "building release "+strconv.Itoa(rel.Number))
	go func() {
		bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Minute)
		defer cancel()
		s.runBuild(bctx, rel, c, src, b)
	}()
	return rel, nil
}

func (s *Server) runBuild(ctx context.Context, rel *store.Release, c *ReleaseSource, src contracts.Source, b buildReq) {
	buildMu.Lock()
	defer buildMu.Unlock()
	fail := func(msg string, checks []release.Check) {
		cj, _ := json.Marshal(checks)
		if checks == nil {
			cj = []byte("[]")
		}
		s.store.FinishRelease(ctx, rel.ID, "failed", cj, nil, "", 0, nil, "", msg)
		rel.Status, rel.Error = "failed", msg
		s.releaseStatus(ctx, c, rel, "failure", msg)
		s.releaseComment(ctx, c, rel, checks)
		s.notifyEvent(ctx, store.Notification{Kind: "release.failed", Severity: "error",
			Title: fmt.Sprintf("%s release %d failed", releaseTitle(rel.Kind), rel.Number), Body: msg, Link: "settings/releases/" + rel.Kind})
	}
	files := b.files
	if files == nil {
		var err error
		if files, err = src.Files(ctx, rel.Revision); err != nil {
			fail("reading the repository failed: "+err.Error(), nil)
			return
		}
	}
	var res *release.Result
	if rel.Kind == release.Modules {
		res = release.BuildModules(ctx, release.ModulesInput{Files: files, Path: c.Path, Tenant: s.cfg.Tenant, Revision: rel.Revision,
			Fetch: &release.Registry{Base: s.cfg.RegistryURL}})
	} else {
		reserved, err := s.store.ConsolePolicyNames(ctx)
		if err != nil {
			fail(err.Error(), nil)
			return
		}
		res = release.BuildPolicies(ctx, release.PoliciesInput{Files: files, Path: c.Path, Tenant: s.cfg.Tenant, Revision: rel.Revision, Reserved: reserved})
	}
	checks, _ := json.Marshal(res.Checks)
	if !res.OK() {
		failed := ""
		for _, ch := range res.Checks {
			if !ch.OK {
				failed = ch.Name
				if len(ch.Errors) > 0 {
					failed += ": " + ch.Errors[0]
				}
				break
			}
		}
		fail("check failed: "+failed, res.Checks)
		return
	}
	if b.after != nil {
		if err := b.after(ctx, rel); err != nil {
			fail("the change built, but committing it failed: "+err.Error(), res.Checks)
			return
		}
		res.Manifest.Revision = rel.Revision
	}
	man, _ := json.Marshal(res.Manifest)
	var inline []byte
	object := ""
	if s.objects != nil {
		object = "releases/" + rel.Kind + "/" + res.SHA256 + ".tar.gz"
		if err := s.objects.Put(ctx, object, res.Bundle); err != nil {
			fail("storing the bundle in the bucket failed: "+err.Error(), res.Checks)
			return
		}
	} else {
		inline = res.Bundle
	}
	if err := s.store.FinishRelease(ctx, rel.ID, "ready", checks, man, res.SHA256, int64(len(res.Bundle)), inline, object, ""); err != nil {
		s.log.Error("recording a release failed", "release", rel.ID, "err", err)
		return
	}
	rel.Status = "ready"
	s.audit(ctx, "system:releases", "release.ready", "releases/"+rel.Kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"sha256": res.SHA256, "size": len(res.Bundle)})
	s.releaseStatus(ctx, c, rel, "pending", fmt.Sprintf("release %d built; waiting for activation (DevOps approval)", rel.Number))
	s.releaseComment(ctx, c, rel, res.Checks)
	s.notifyEvent(ctx, store.Notification{Kind: "release.ready", Severity: "action",
		Title: fmt.Sprintf("%s release %d is ready", releaseTitle(rel.Kind), rel.Number),
		Body:  fmt.Sprintf("%s · every check passed. Request activation to have DevOps approve it.", rel.Title), Link: "settings/releases/" + rel.Kind + "/" + rel.ID})
}

// ---- deploying ----

// deploy makes a release active. A module release is checked once more and
// its bundle is read through the cache before anything switches, so a
// release whose bundle cannot be read is never deployed.
func (s *Server) deploy(ctx context.Context, rel *store.Release, actor string) (*store.Release, error) {
	var m release.Manifest
	if err := json.Unmarshal(rel.Manifest, &m); err != nil || rel.SHA256 == "" {
		return nil, errors.New("the release has no manifest; only a successfully built release can be deployed")
	}
	if m.Tenant != s.cfg.Tenant {
		return nil, fmt.Errorf("the release was built for tenant %s", m.Tenant)
	}
	var next *platform
	var sets []store.ReleasePolicySet
	if rel.Kind == release.Modules {
		var err error
		if next, err = platformFromRelease(rel, &m); err != nil {
			return nil, err
		}
		if _, err := s.bundles.Get(ctx, rel.SHA256); err != nil {
			return nil, fmt.Errorf("the release bundle cannot be read: %w", err)
		}
	} else {
		for _, p := range m.Policies {
			sets = append(sets, store.ReleasePolicySet{Name: p.Name, Scope: p.Scope, Level: p.Level, Module: p.Module})
		}
	}
	out, err := s.store.DeployRelease(ctx, rel.ID, actor, sets)
	if err != nil {
		return nil, err
	}
	if next != nil {
		s.platSnap.Store(next)
		s.refreshAssistantDocs()
	}
	s.audit(ctx, actor, "release.deploy", "releases/"+rel.Kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"sha256": rel.SHA256, "revision": rel.Revision})
	s.notifyEvent(ctx, store.Notification{Kind: "release.deployed", Severity: "success",
		Title: fmt.Sprintf("%s release %d deployed", releaseTitle(rel.Kind), rel.Number), Body: "Deployed by " + actor + ".", Link: "settings/releases/" + rel.Kind})
	return out, nil
}

func platformFromRelease(rel *store.Release, m *release.Manifest) (*platform, error) {
	if m.Catalog == nil {
		return nil, errors.New("the release has no catalog")
	}
	cat, err := catalog.New(m.Catalog.Modules, m.Catalog.Providers)
	if err != nil {
		return nil, fmt.Errorf("the release catalog is invalid: %w", err)
	}
	ov := m.Defaults
	if ov == nil {
		ov = &catalog.Overlay{Tenant: m.Tenant, Kinds: map[string]*catalog.Defaults{}}
	}
	if err := spec.ValidateOverlay(cat, ov); err != nil {
		return nil, fmt.Errorf("the release defaults are invalid: %w", err)
	}
	return &platform{cat: cat, defaults: ov, release: &releaseInfo{ID: rel.ID, Number: rel.Number, SHA256: rel.SHA256, manifest: m}}, nil
}

// loadActiveRelease switches to the deployed module release at startup. It
// reads only the manifest; bundles are fetched (and cached) when runs need them.
func (s *Server) loadActiveRelease(ctx context.Context) {
	s.store.FailInterruptedBuilds(ctx, 30*time.Minute)
	rel, err := s.store.ActiveRelease(ctx, release.Modules)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("loading the deployed module release failed; using the bundled catalog", "err", err)
		}
		return
	}
	var m release.Manifest
	if err := json.Unmarshal(rel.Manifest, &m); err != nil {
		s.log.Error("the deployed module release has an unreadable manifest; using the bundled catalog", "release", rel.Number, "err", err)
		return
	}
	p, err := platformFromRelease(rel, &m)
	if err != nil {
		s.log.Error("the deployed module release is invalid; using the bundled catalog", "release", rel.Number, "err", err)
		return
	}
	s.platSnap.Store(p)
	s.log.Info("module release deployed", "release", rel.Number, "sha256", rel.SHA256[:12], "kinds", len(p.cat.Modules), "defaults", len(p.defaults.Kinds))
}

// loadBundle reads a bundle from where builds put it: the tenant bucket or PostgreSQL.
func (s *Server) loadBundle(ctx context.Context, sha string) ([]byte, error) {
	inline, object, err := s.store.ReleaseBundle(ctx, sha)
	if err != nil {
		return nil, err
	}
	if object != "" {
		if s.objects == nil {
			return nil, errors.New("the bundle is in a bucket, but no bucket is configured")
		}
		return s.objects.Get(ctx, object)
	}
	return inline, nil
}

// agentBundle serves a release bundle to a runner with a claimed run.
func (s *Server) agentBundle(w http.ResponseWriter, r *http.Request) {
	sha := r.PathValue("sha")
	b, err := s.bundles.Get(r.Context(), sha)
	if err != nil {
		s.writeStoreErr(w, err, "")
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("ETag", `"`+sha+`"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.Write(b)
}

// releaseSyncer builds automatically when a source's branch moves (for
// sources with Enabled), by polling; the GitHub push webhook does the same
// without waiting.
func (s *Server) releaseSyncer(ctx context.Context) {
	last := map[string]time.Time{}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, kind := range []string{release.Modules, release.Policies} {
			c, ok := s.releaseSource(ctx, kind)
			if !ok || !c.Enabled || time.Since(last[kind]) < time.Duration(c.PollSeconds)*time.Second {
				continue
			}
			last[kind] = time.Now()
			s.buildIfMoved(ctx, kind)
		}
	}
}

// buildIfMoved starts a build when the branch has a commit no release was built from.
func (s *Server) buildIfMoved(ctx context.Context, kind string) {
	c, ok := s.releaseSource(ctx, kind)
	if !ok {
		return
	}
	src, err := s.releaseGit(ctx, kind, c)
	if err != nil {
		return
	}
	rev, err := src.Revision(ctx)
	if err != nil {
		s.log.Warn("checking the release repository failed", "kind", kind, "err", err)
		return
	}
	if built, err := s.store.ReleaseBuilt(ctx, kind, rev); err != nil || built {
		return // already built, or the merge commit of a release the platform activated
	}
	if _, err := s.startBuild(ctx, c, src, buildReq{kind: kind, actor: "system:releases", rev: rev,
		origin: store.ReleaseOrigin{Origin: "branch", Ref: c.Branch, Title: "branch " + c.Branch}}); err != nil && !errors.Is(err, store.ErrConflict) {
		s.log.Warn("starting a release build failed", "kind", kind, "err", err)
	}
}

// releasePush handles a push to a release repository: kinds whose source is
// that repository and branch, with automatic builds enabled.
func (s *Server) releasePush(ctx context.Context, repo, ref string) []string {
	var started []string
	for _, kind := range []string{release.Modules, release.Policies} {
		c, ok := s.releaseSource(ctx, kind)
		if !ok || !c.Enabled || c.Provider != "github" || !strings.EqualFold(c.Repo, repo) || ref != "refs/heads/"+c.Branch {
			continue
		}
		go func(kind string) {
			bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			s.buildIfMoved(bctx, kind)
		}(kind)
		started = append(started, kind)
	}
	return started
}

func releaseTitle(kind string) string {
	if kind == release.Policies {
		return "Policy"
	}
	return "Module"
}
