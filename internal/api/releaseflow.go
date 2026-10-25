package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/contracts"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/githubapp"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/release"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

// How a module or policy release reaches production:
//
//   - Git first: a pull request (or a push to the source branch) in the
//     modules or policies repository is built automatically.
//   - Console first: an edit made in the console (a kind, the tenant's
//     defaults, a policy set) is built at once on top of the branch; only a
//     change that builds is committed, to a new branch with a pull request.
//
// Either way a person picks a built release and requests its activation,
// DevOps approves it (as many approvals as the source asks for, never the
// requester or the author of the change), and the release becomes active.
// Activating a release built from a pull request squash-merges that pull
// request, and only if its head is still the commit that was built.

// releaseEditor: tenant admins and DevOps edit, build and request releases.
func releaseEditor(w http.ResponseWriter, r *http.Request) bool {
	if p := user(r); p.HasTenantRole(identity.TenantAdmin, identity.DevOps) {
		return true
	}
	writeErr(w, http.StatusForbidden, "this needs the tenant_admin or devops role")
	return false
}

func (s *Server) releaseOf(w http.ResponseWriter, r *http.Request) (*store.Release, *ReleaseSource, bool) {
	kind, ok := releaseKind(w, r)
	if !ok {
		return nil, nil, false
	}
	rel, err := s.store.GetRelease(r.Context(), r.PathValue("id"))
	if err == nil && rel.Kind != kind {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writeStoreErr(w, err, "")
		return nil, nil, false
	}
	c, ok := s.releaseSource(r.Context(), kind)
	if !ok {
		writeErr(w, http.StatusConflict, "no "+kind+" repository is configured")
		return nil, nil, false
	}
	return rel, c, true
}

// requestActivation asks DevOps to approve activating a built release. With
// no approvals required, it activates at once.
func (s *Server) requestActivation(w http.ResponseWriter, r *http.Request) {
	if !releaseEditor(w, r) {
		return
	}
	rel, c, ok := s.releaseOf(w, r)
	if !ok {
		return
	}
	actor := user(r).Actor()
	if err := s.store.RequestActivation(r.Context(), rel.ID, user(r).Subject); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "another "+rel.Kind+" release is already waiting for approval; approve, reject or wait for it first")
			return
		}
		writeErr(w, 422, err.Error())
		return
	}
	s.audit(r.Context(), actor, "release.request", "releases/"+rel.Kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"approvals_needed": c.Approvals})
	if c.Approvals == 0 {
		out, err := s.activate(r.Context(), rel, c, actor)
		if err != nil {
			writeErr(w, 422, "the release cannot be activated", err.Error())
			return
		}
		writeJSON(w, 200, out)
		return
	}
	s.notifyEvent(r.Context(), store.Notification{Kind: "release.requested", Severity: "action",
		Title: fmt.Sprintf("Approve activating %s release %d", strings.ToLower(releaseTitle(rel.Kind)), rel.Number),
		Body:  fmt.Sprintf("%s asks to activate %s. %d DevOps approval(s) needed.", user(r).Subject, rel.Title, c.Approvals),
		Link:  "settings/releases/" + rel.Kind + "/" + rel.ID})
	out, _ := s.store.GetRelease(r.Context(), rel.ID)
	writeJSON(w, 200, out)
}

func (s *Server) approveRelease(w http.ResponseWriter, r *http.Request) {
	s.decideRelease(w, r, "approve")
}
func (s *Server) rejectRelease(w http.ResponseWriter, r *http.Request) {
	s.decideRelease(w, r, "reject")
}

// decideRelease records a DevOps decision. Enough approvals activate the release.
func (s *Server) decideRelease(w http.ResponseWriter, r *http.Request, decision string) {
	p := user(r)
	if !p.HasTenantRole(identity.DevOps) {
		writeErr(w, http.StatusForbidden, "approving releases needs the devops role")
		return
	}
	rel, c, ok := s.releaseOf(w, r)
	if !ok {
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if r.ContentLength != 0 && !decode(w, r, &b) {
		return
	}
	if decision == "approve" {
		switch {
		case rel.RequestedBy == p.Subject:
			writeErr(w, http.StatusForbidden, "you requested this activation; another DevOps engineer must approve it")
			return
		case rel.Origin == "console" && rel.CreatedBy == p.Actor():
			writeErr(w, http.StatusForbidden, "you made this change; another DevOps engineer must approve it")
			return
		}
	}
	n, err := s.store.DecideRelease(r.Context(), rel.ID, p.Subject, decision, b.Reason)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeErr(w, http.StatusConflict, "you already decided on this request")
			return
		}
		writeErr(w, 422, err.Error())
		return
	}
	s.audit(r.Context(), p.Actor(), "release."+decision, "releases/"+rel.Kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"reason": b.Reason, "approvals": n})
	if decision == "reject" {
		s.notifyEvent(r.Context(), store.Notification{Kind: "release.rejected", Severity: "warning",
			Title: fmt.Sprintf("Activation of %s release %d rejected", strings.ToLower(releaseTitle(rel.Kind)), rel.Number),
			Body:  fmt.Sprintf("Rejected by %s: %s", p.Subject, b.Reason), Link: "settings/releases/" + rel.Kind + "/" + rel.ID})
	} else if n >= max(c.Approvals, 1) {
		if _, err := s.activate(r.Context(), rel, c, "approved:"+p.Subject); err != nil {
			writeErr(w, 422, "approved, but the release cannot be activated", err.Error())
			return
		}
	}
	out, _ := s.store.GetRelease(r.Context(), rel.ID)
	writeJSON(w, 200, out)
}

// overrideRelease lets DevOps activate a release that waits for approvals
// without them. The reason is recorded with the release and in the audit log.
func (s *Server) overrideRelease(w http.ResponseWriter, r *http.Request) {
	p := user(r)
	if !p.HasTenantRole(identity.DevOps) {
		writeErr(w, http.StatusForbidden, "overriding approvals needs the devops role")
		return
	}
	rel, c, ok := s.releaseOf(w, r)
	if !ok {
		return
	}
	var b struct {
		Reason string `json:"reason"`
	}
	if !decode(w, r, &b) {
		return
	}
	if strings.TrimSpace(b.Reason) == "" {
		writeErr(w, 422, "an override needs a reason")
		return
	}
	if rel.Status != "pending" {
		writeErr(w, http.StatusConflict, "only a release waiting for approval can be overridden")
		return
	}
	if _, err := s.store.DecideRelease(r.Context(), rel.ID, p.Subject, "override", b.Reason); err != nil && !errors.Is(err, store.ErrConflict) {
		writeErr(w, 422, err.Error())
		return
	}
	s.audit(r.Context(), p.Actor(), "release.override", "releases/"+rel.Kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"reason": b.Reason})
	out, err := s.activate(r.Context(), rel, c, "override:"+p.Subject)
	if err != nil {
		writeErr(w, 422, "the release cannot be activated", err.Error())
		return
	}
	writeJSON(w, 200, out)
}

// activate deploys a release and, for a pull-request release, merges its pull request.
func (s *Server) activate(ctx context.Context, rel *store.Release, c *ReleaseSource, actor string) (*store.Release, error) {
	full, err := s.store.GetRelease(ctx, rel.ID)
	if err != nil {
		return nil, err
	}
	out, err := s.deploy(ctx, full, actor)
	if err != nil {
		return nil, err
	}
	s.releaseStatus(ctx, c, out, "success", fmt.Sprintf("activated as release %d", out.Number))
	if out.PRNumber != nil && out.MergeSHA == "" {
		if err := s.mergeReleasePR(ctx, out, c); err != nil {
			s.store.SetReleaseMerge(ctx, out.ID, "", err.Error())
			s.notifyEvent(ctx, store.Notification{Kind: "release.merge_failed", Severity: "error",
				Title: fmt.Sprintf("%s release %d is active, but its pull request was not merged", releaseTitle(out.Kind), out.Number),
				Body:  err.Error(), Link: "settings/releases/" + out.Kind + "/" + out.ID})
		}
	}
	return s.store.GetRelease(ctx, rel.ID)
}

// mergeReleasePR squash-merges a release's pull request at exactly the built commit.
func (s *Server) mergeReleasePR(ctx context.Context, rel *store.Release, c *ReleaseSource) error {
	app, inst, err := s.releaseGitHub(ctx, c)
	if err != nil {
		return err
	}
	pr, err := app.GetPR(ctx, inst, c.Repo, *rel.PRNumber)
	if err != nil {
		return err
	}
	if pr.Merged {
		s.store.SetReleaseMerge(ctx, rel.ID, "already-merged", "")
		return nil
	}
	if pr.State != "open" {
		return fmt.Errorf("pull request #%d is %s", pr.Number, pr.State)
	}
	if pr.Head.SHA != rel.Revision {
		return fmt.Errorf("pull request #%d moved on to %s after release %d was built from %s; it was not merged", pr.Number, short(pr.Head.SHA), rel.Number, short(rel.Revision))
	}
	sha, err := app.MergeSHA(ctx, inst, c.Repo, pr.Number, rel.Revision,
		fmt.Sprintf("%s (#%d)", pr.Title, pr.Number), fmt.Sprintf("Activated in Cloud Pravaha as %s release %d after DevOps approval.", strings.ToLower(releaseTitle(rel.Kind)), rel.Number))
	if err != nil {
		return err
	}
	if sha == "" {
		sha = "merged"
	}
	s.store.SetReleaseMerge(ctx, rel.ID, sha, "")
	s.audit(ctx, "system:releases", "release.merge", "releases/"+rel.Kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"pr": pr.Number, "merge_sha": sha})
	return nil
}

// retryMerge merges the pull request of an active release whose merge failed.
func (s *Server) retryMerge(w http.ResponseWriter, r *http.Request) {
	if !releaseEditor(w, r) {
		return
	}
	rel, c, ok := s.releaseOf(w, r)
	if !ok {
		return
	}
	if rel.Status != "active" || rel.PRNumber == nil || rel.MergeSHA != "" {
		writeErr(w, http.StatusConflict, "only an active release with an unmerged pull request can be merged")
		return
	}
	if err := s.mergeReleasePR(r.Context(), rel, c); err != nil {
		s.store.SetReleaseMerge(r.Context(), rel.ID, "", err.Error())
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	out, _ := s.store.GetRelease(r.Context(), rel.ID)
	writeJSON(w, 200, out)
}

// ---- GitHub: statuses, comments, pull requests ----

func (s *Server) releaseGitHub(ctx context.Context, c *ReleaseSource) (*githubapp.App, int64, error) {
	if c.Provider != "github" || c.Auth != "github_app" {
		return nil, 0, errors.New("pull requests need a GitHub repository that authenticates with the GitHub App")
	}
	app, gcfg, err := s.githubApp(ctx)
	if err != nil {
		return nil, 0, err
	}
	inst := gcfg.InstallationID
	if inst == 0 {
		i, err := app.RepoInstallation(ctx, c.Repo)
		if err != nil {
			return nil, 0, err
		}
		inst = i.ID
	}
	return app, inst, nil
}

func statusContext(kind string) string { return "pravaha/release-" + kind }

func (s *Server) releaseLink(rel *store.Release) string {
	return strings.TrimRight(s.cfg.CentralURL, "/") + "/#/t/" + s.cfg.Tenant + "/settings/releases/" + rel.Kind + "/" + rel.ID
}

// releaseStatus sets the commit status of a pull-request release (best effort).
func (s *Server) releaseStatus(ctx context.Context, c *ReleaseSource, rel *store.Release, state, desc string) {
	if rel.PRNumber == nil && rel.Origin != "pr" {
		return
	}
	app, inst, err := s.releaseGitHub(ctx, c)
	if err != nil || len(rel.Revision) != 40 {
		return
	}
	if err := app.SetStatus(ctx, inst, c.Repo, rel.Revision, state, statusContext(rel.Kind), desc, s.releaseLink(rel)); err != nil {
		s.log.Warn("setting the release status failed", "release", rel.ID, "err", err)
	}
}

// releaseComment keeps one comment per pull request with the latest build's checks.
func (s *Server) releaseComment(ctx context.Context, c *ReleaseSource, rel *store.Release, checks []release.Check) {
	if rel.PRNumber == nil {
		return
	}
	app, inst, err := s.releaseGitHub(ctx, c)
	if err != nil {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "### Cloud Pravaha · %s release %d — %s\n\n", strings.ToLower(releaseTitle(rel.Kind)), rel.Number, rel.Status)
	fmt.Fprintf(&b, "Built from `%s`.\n\n", short(rel.Revision))
	for _, ch := range checks {
		mark := "✅"
		if !ch.OK {
			mark = "❌"
		}
		fmt.Fprintf(&b, "- %s **%s**", mark, ch.Name)
		if ch.Detail != "" {
			fmt.Fprintf(&b, " — %s", ch.Detail)
		}
		b.WriteString("\n")
		for i, e := range ch.Errors {
			if i == 10 {
				fmt.Fprintf(&b, "  - … %d more\n", len(ch.Errors)-10)
				break
			}
			fmt.Fprintf(&b, "  - `%s`\n", strings.ReplaceAll(e, "`", "'"))
		}
	}
	if rel.Status == "ready" {
		b.WriteString("\nNext: request activation in Cloud Pravaha. DevOps approves it, the release becomes active, and this pull request is merged automatically.\n")
	}
	fmt.Fprintf(&b, "\n[Open in Cloud Pravaha](%s)\n", s.releaseLink(rel))
	key := fmt.Sprintf("release_comment_%s_%d", rel.Kind, *rel.PRNumber)
	var prev struct {
		ID int64 `json:"id"`
	}
	s.store.Setting(ctx, key, &prev)
	id, err := app.Comment(ctx, inst, c.Repo, *rel.PRNumber, prev.ID, b.String())
	if err != nil {
		s.log.Warn("commenting on the release pull request failed", "release", rel.ID, "err", err)
		return
	}
	if id != prev.ID {
		s.store.PutSetting(ctx, key, map[string]int64{"id": id}, "system:releases")
	}
}

// releasePullRequest handles a pull_request webhook for a modules or
// policies repository. handled is false when the repository is neither.
func (s *Server) releasePullRequest(ctx context.Context, repo, action string, body []byte) (handled bool, outcome, detail string) {
	var ev struct {
		Number      int `json:"number"`
		PullRequest struct {
			Number  int    `json:"number"`
			Title   string `json:"title"`
			HTMLURL string `json:"html_url"`
			Draft   bool   `json:"draft"`
			Merged  bool   `json:"merged"`
			Head    struct {
				SHA  string `json:"sha"`
				Ref  string `json:"ref"`
				Repo struct {
					FullName string `json:"full_name"`
				} `json:"repo"`
			} `json:"head"`
			Base struct {
				Ref string `json:"ref"`
			} `json:"base"`
		} `json:"pull_request"`
	}
	json.Unmarshal(body, &ev)
	pr := ev.PullRequest
	if pr.Number == 0 {
		pr.Number = ev.Number
	}
	var notes []string
	for _, kind := range []string{release.Modules, release.Policies} {
		c, ok := s.releaseSource(ctx, kind)
		if !ok || c.Provider != "github" || !strings.EqualFold(c.Repo, repo) {
			continue
		}
		handled = true
		if pr.Base.Ref != c.Branch {
			notes = append(notes, fmt.Sprintf("%s: pull request targets %s, releases follow %s", kind, pr.Base.Ref, c.Branch))
			continue
		}
		switch action {
		case "closed":
			if !pr.Merged {
				n, _ := s.store.DiscardPRReleases(ctx, kind, pr.Number, "", "the pull request was closed without merging")
				notes = append(notes, fmt.Sprintf("%s: pull request #%d closed; %d build(s) retired", kind, pr.Number, n))
			} else {
				notes = append(notes, fmt.Sprintf("%s: pull request #%d merged", kind, pr.Number))
			}
		case "opened", "synchronize", "reopened", "ready_for_review":
			switch {
			case !c.Enabled:
				notes = append(notes, kind+": automatic builds are off for this repository")
			case pr.Draft:
				notes = append(notes, fmt.Sprintf("%s: pull request #%d is a draft; it is built once it is ready for review", kind, pr.Number))
			case pr.Head.Repo.FullName != "" && !strings.EqualFold(pr.Head.Repo.FullName, c.Repo):
				notes = append(notes, fmt.Sprintf("%s: pull request #%d comes from a fork; forks are never built", kind, pr.Number))
			default:
				s.store.DiscardPRReleases(ctx, kind, pr.Number, pr.Head.SHA, "superseded by a newer commit of the pull request")
				if built, err := s.store.ReleaseBuilt(ctx, kind, pr.Head.SHA); err == nil && built {
					notes = append(notes, fmt.Sprintf("%s: %s is already built", kind, short(pr.Head.SHA)))
					continue
				}
				src, err := s.releaseGit(ctx, kind, c)
				if err == nil {
					_, err = s.startBuild(ctx, c, src, buildReq{kind: kind, actor: "github:pr#" + strconv.Itoa(pr.Number), rev: pr.Head.SHA,
						origin: store.ReleaseOrigin{Origin: "pr", Ref: pr.Head.Ref, PRNumber: pr.Number, PRURL: pr.HTMLURL, Title: pr.Title}})
				}
				if err != nil {
					notes = append(notes, fmt.Sprintf("%s: building pull request #%d failed to start: %v", kind, pr.Number, err))
					continue
				}
				notes = append(notes, fmt.Sprintf("%s: building pull request #%d at %s", kind, pr.Number, short(pr.Head.SHA)))
			}
		default:
			notes = append(notes, fmt.Sprintf("%s: pull request #%d %s", kind, pr.Number, action))
		}
	}
	if !handled {
		return false, "", ""
	}
	return true, "processed", strings.Join(notes, "; ")
}

// ---- console changes ----

// snapshot caches the latest branch snapshot per kind, so opening several
// files in the editor reads the repository once per commit.
var snapshots = struct {
	sync.Mutex
	m map[string]struct {
		rev   string
		files map[string][]byte
	}
}{m: map[string]struct {
	rev   string
	files map[string][]byte
}{}}

func (s *Server) branchSnapshot(ctx context.Context, kind string, src contracts.Source) (string, map[string][]byte, error) {
	rev, err := src.Revision(ctx)
	if err != nil {
		return "", nil, err
	}
	snapshots.Lock()
	cached, ok := snapshots.m[kind]
	snapshots.Unlock()
	if ok && cached.rev == rev {
		return rev, cached.files, nil
	}
	files, err := src.Files(ctx, rev)
	if err != nil {
		return "", nil, err
	}
	snapshots.Lock()
	snapshots.m[kind] = struct {
		rev   string
		files map[string][]byte
	}{rev, files}
	snapshots.Unlock()
	return rev, files, nil
}

// editablePath checks a path relative to the source folder and returns the
// repository path.
func editablePath(c *ReleaseSource, kind, p string) (string, error) {
	clean := path.Clean(strings.TrimPrefix(p, "/"))
	if clean != p || clean == "." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "..") {
		return "", fmt.Errorf("path %q is not allowed", p)
	}
	ext := path.Ext(clean)
	allowed := map[string]bool{".yaml": true, ".yml": true}
	if kind == release.Policies {
		allowed[".rego"] = true
	}
	if !allowed[ext] {
		return "", fmt.Errorf("%s: only %v files can be edited here", p, sortedExts(allowed))
	}
	if kind == release.Modules && !strings.HasPrefix(clean, "catalog/") && !strings.HasPrefix(clean, "tenants/") {
		return "", fmt.Errorf("%s: module changes edit catalog/ or tenants/ files", p)
	}
	return path.Join(strings.Trim(c.Path, "/"), clean), nil
}

func sortedExts(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// getReleaseFile returns a file of the source branch (paths relative to the source folder).
func (s *Server) getReleaseFile(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok || !releaseEditor(w, r) {
		return
	}
	c, src, err := s.releaseRepo(r.Context(), kind)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	p := r.URL.Query().Get("path")
	repoPath, err := editablePath(c, kind, p)
	if err != nil {
		writeErr(w, 422, err.Error())
		return
	}
	rev, files, err := s.branchSnapshot(r.Context(), kind, src)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "reading the repository failed: "+err.Error())
		return
	}
	resp := map[string]any{"path": p, "revision": rev, "exists": false}
	if b, ok := files[repoPath]; ok {
		resp["exists"], resp["content"] = true, string(b)
	}
	writeJSON(w, 200, resp)
}

// proposeReleaseChange builds a console change on top of the source branch
// and, when every check passes, commits it as a pull request.
func (s *Server) proposeReleaseChange(w http.ResponseWriter, r *http.Request) {
	kind, ok := releaseKind(w, r)
	if !ok || !releaseEditor(w, r) {
		return
	}
	var b struct {
		Title string             `json:"title"`
		Body  string             `json:"body"`
		Files map[string]*string `json:"files"` // path -> new content; null deletes the file
	}
	if !decode(w, r, &b) {
		return
	}
	if len(b.Files) == 0 || len(b.Files) > 20 {
		writeErr(w, 422, "a change edits between 1 and 20 files")
		return
	}
	ctx := r.Context()
	c, src, err := s.releaseRepo(ctx, kind)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if c.Provider == "github" {
		if _, _, err := s.releaseGitHub(ctx, c); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	} else if c.Provider != "local" {
		writeErr(w, http.StatusConflict, "console changes are committed as GitHub pull requests; connect the repository through the GitHub App")
		return
	}
	rev, base, err := s.branchSnapshot(ctx, kind, src)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "reading the repository failed: "+err.Error())
		return
	}
	files := make(map[string][]byte, len(base))
	for k, v := range base {
		files[k] = v
	}
	changes := map[string]*string{} // repo path -> content
	var names []string
	for p, content := range b.Files {
		repoPath, err := editablePath(c, kind, p)
		if err != nil {
			writeErr(w, 422, err.Error())
			return
		}
		if content != nil && len(*content) > 256<<10 {
			writeErr(w, 422, p+" is larger than 256 KiB")
			return
		}
		old, existed := base[repoPath]
		if content == nil && !existed || content != nil && existed && bytes.Equal(old, []byte(*content)) {
			continue
		}
		changes[repoPath] = content
		names = append(names, p)
		if content == nil {
			delete(files, repoPath)
		} else {
			files[repoPath] = []byte(*content)
		}
	}
	if len(changes) == 0 {
		writeErr(w, 422, "nothing changed")
		return
	}
	sort.Strings(names)
	title := strings.TrimSpace(b.Title)
	if title == "" {
		title = "Update " + strings.Join(names, ", ")
	}
	if len(title) > 200 {
		title = title[:200]
	}
	actor := user(r).Actor()
	author := user(r).Subject
	rel, err := s.startBuild(ctx, c, src, buildReq{kind: kind, actor: actor, rev: rev, files: files,
		origin: store.ReleaseOrigin{Origin: "console", Ref: c.Branch, Title: title},
		after: func(ctx context.Context, rel *store.Release) error {
			return s.commitChange(ctx, c, rel, changes, title, b.Body, author)
		}})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(ctx, actor, "release.change", "releases/"+kind+"/"+strconv.Itoa(rel.Number), "", map[string]any{"files": names, "title": title})
	writeJSON(w, 202, rel)
}

// commitChange commits a change that built: a branch, one commit per file and
// a pull request on GitHub, or the files themselves for the development-only
// local provider (which has no pull requests).
func (s *Server) commitChange(ctx context.Context, c *ReleaseSource, rel *store.Release, changes map[string]*string, title, body, author string) error {
	paths := make([]string, 0, len(changes))
	for p := range changes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if c.Provider == "local" {
		for _, p := range paths {
			full := filepath.Join(c.Repo, filepath.FromSlash(p))
			if changes[p] == nil {
				if err := os.Remove(full); err != nil && !os.IsNotExist(err) {
					return err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(full, []byte(*changes[p]), 0o644); err != nil {
				return err
			}
		}
		src, err := s.releaseGit(ctx, rel.Kind, c)
		if err != nil {
			return err
		}
		rev, err := src.Revision(ctx)
		if err != nil {
			return err
		}
		rel.Revision = rev
		return s.store.SetReleasePR(ctx, rel.ID, rev, 0, "", c.Branch)
	}
	app, inst, err := s.releaseGitHub(ctx, c)
	if err != nil {
		return err
	}
	rnd := make([]byte, 3)
	rand.Read(rnd)
	branch := fmt.Sprintf("pravaha/%s-%d-%s", rel.Kind, rel.Number, hex.EncodeToString(rnd))
	base, err := app.BranchSHA(ctx, inst, c.Repo, c.Branch)
	if err == nil {
		err = app.CreateBranch(ctx, inst, c.Repo, branch, base)
	}
	msg := fmt.Sprintf("%s (requested by %s in Cloud Pravaha)", title, author)
	for _, p := range paths {
		if err != nil {
			break
		}
		var sha string
		if sha, err = app.FileSHA(ctx, inst, c.Repo, p, branch); err != nil {
			break
		}
		if changes[p] == nil {
			if sha != "" {
				err = app.DeleteFile(ctx, inst, c.Repo, p, branch, msg, sha)
			}
		} else {
			err = app.PutFile(ctx, inst, c.Repo, p, branch, msg, []byte(*changes[p]), sha)
		}
	}
	var head string
	if err == nil {
		head, err = app.BranchSHA(ctx, inst, c.Repo, branch)
	}
	if err != nil {
		return err
	}
	// Record the commit before the pull request exists, so its webhook finds
	// the commit already built and does not build it again.
	rel.Revision = head
	if err := s.store.SetReleasePR(ctx, rel.ID, head, 0, "", branch); err != nil {
		return err
	}
	prBody := fmt.Sprintf("Changed in Cloud Pravaha by **%s**; built and checked before this pull request was opened.\n\n%s\n\nFiles:\n", author, strings.TrimSpace(body))
	for _, p := range paths {
		prBody += "- `" + p + "`\n"
	}
	prBody += "\nIt merges automatically once DevOps approves activating the release."
	pr, err := app.OpenPR(ctx, inst, c.Repo, branch, c.Branch, title, prBody)
	if err != nil {
		return err
	}
	n := pr.Number
	rel.PRNumber, rel.PRURL = &n, pr.HTMLURL
	return s.store.SetReleasePR(ctx, rel.ID, head, n, pr.HTMLURL, branch)
}
