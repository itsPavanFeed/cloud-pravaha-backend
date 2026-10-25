package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Release is a module or policy release built from Git.
type Release struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"` // modules | policies
	Number     int             `json:"number"`
	Revision   string          `json:"revision"`
	Status     string          `json:"status"` // building | failed | ready | active | superseded
	Checks     json.RawMessage `json:"checks"`
	Manifest   json.RawMessage `json:"manifest,omitempty"`
	SHA256     string          `json:"sha256,omitempty"`
	Size       int64           `json:"size,omitempty"`
	Error      string          `json:"error,omitempty"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	DeployedBy string          `json:"deployed_by,omitempty"`
	DeployedAt *time.Time      `json:"deployed_at,omitempty"`

	Origin      string            `json:"origin"` // branch | pr | console
	Ref         string            `json:"ref,omitempty"`
	PRNumber    *int              `json:"pr_number,omitempty"`
	PRURL       string            `json:"pr_url,omitempty"`
	Title       string            `json:"title,omitempty"`
	RequestedBy string            `json:"requested_by,omitempty"`
	RequestedAt *time.Time        `json:"requested_at,omitempty"`
	MergeSHA    string            `json:"merge_sha,omitempty"`
	MergeError  string            `json:"merge_error,omitempty"`
	Approvals   []ReleaseApproval `json:"approvals"`
}

// ReleaseApproval is one DevOps decision on an activation request.
type ReleaseApproval struct {
	Approver  string    `json:"approver"`
	Decision  string    `json:"decision"` // approve | reject
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ReleaseOrigin describes where a build comes from.
type ReleaseOrigin struct {
	Origin, Ref, PRURL, Title string
	PRNumber                  int
}

const relCols = `id, kind, number, revision, status, checks, COALESCE(sha256, ''), COALESCE(size, 0), COALESCE(error, ''),
	created_by, created_at, finished_at, COALESCE(deployed_by, ''), deployed_at,
	origin, ref, pr_number, COALESCE(pr_url, ''), title, COALESCE(requested_by, ''), requested_at, COALESCE(merge_sha, ''), COALESCE(merge_error, '')`

func scanRelease(r pgx.Row) (*Release, error) {
	return scanReleaseWith(r, nil)
}

// StartRelease records a new build.
func (s *Store) StartRelease(ctx context.Context, kind, revision, by string, o ReleaseOrigin) (*Release, error) {
	if o.Origin == "" {
		o.Origin = "branch"
	}
	var pr *int
	if o.PRNumber > 0 {
		pr = &o.PRNumber
	}
	r, err := scanRelease(s.db.QueryRow(ctx, `INSERT INTO releases (kind, number, revision, status, created_by, origin, ref, pr_number, pr_url, title)
		VALUES ($1, COALESCE((SELECT max(number) FROM releases WHERE kind = $1), 0) + 1, $2, 'building', $3, $4, $5, $6, NULLIF($7, ''), $8)
		RETURNING `+relCols, kind, revision, by, o.Origin, o.Ref, pr, o.PRURL, o.Title))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return r, err
}

// ReleaseBuilt reports whether a commit already has a build that did not fail
// or get discarded, or is a merge commit the platform made itself.
func (s *Store) ReleaseBuilt(ctx context.Context, kind, revision string) (bool, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM releases WHERE kind = $1 AND (merge_sha = $2 OR revision = $2 AND status NOT IN ('failed', 'discarded'))`, kind, revision).Scan(&n)
	return n > 0, err
}

// SetReleasePR records the pull request a console change was committed to.
func (s *Store) SetReleasePR(ctx context.Context, id, revision string, number int, url, ref string) error {
	_, err := s.db.Exec(ctx, `UPDATE releases SET revision = $2, pr_number = NULLIF($3, 0), pr_url = NULLIF($4, ''), ref = $5 WHERE id = $1`, id, revision, number, url, ref)
	return err
}

// DiscardPRReleases retires the builds of a pull request that can no longer be
// activated (closed, or superseded by a newer commit than keepRevision).
func (s *Store) DiscardPRReleases(ctx context.Context, kind string, pr int, keepRevision, why string) (int64, error) {
	t, err := s.db.Exec(ctx, `UPDATE releases SET status = 'discarded', error = $4, requested_by = NULL, requested_at = NULL
		WHERE kind = $1 AND pr_number = $2 AND revision <> $3 AND status IN ('ready', 'pending')`, kind, pr, keepRevision, why)
	return t.RowsAffected(), err
}

// RequestActivation asks DevOps to approve activating a built release. One
// request per kind is open at a time.
func (s *Store) RequestActivation(ctx context.Context, id, by string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	t, err := tx.Exec(ctx, `UPDATE releases SET status = 'pending', requested_by = $2, requested_at = now()
		WHERE id::text = $1 AND status IN ('ready', 'superseded')`, id, by)
	if IsUnique(err) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	if t.RowsAffected() == 0 {
		return errors.New("only a successfully built release that is not active can be requested")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM release_approvals WHERE release_id::text = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DecideRelease records a DevOps decision on a pending request and returns the
// number of approvals. A rejection closes the request.
func (s *Store) DecideRelease(ctx context.Context, id, approver, decision, reason string) (int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM releases WHERE id::text = $1 FOR UPDATE`, id).Scan(&status); err != nil {
		return 0, NotFound(err)
	}
	if status != "pending" {
		return 0, errors.New("the release has no open activation request")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO release_approvals (release_id, approver, decision, reason) VALUES ($1::uuid, $2, $3, $4)`, id, approver, decision, reason); err != nil {
		if IsUnique(err) {
			return 0, ErrConflict
		}
		return 0, err
	}
	if decision == "reject" {
		if _, err := tx.Exec(ctx, `UPDATE releases SET status = CASE WHEN deployed_at IS NULL THEN 'ready' ELSE 'superseded' END,
			requested_by = NULL, requested_at = NULL WHERE id::text = $1`, id); err != nil {
			return 0, err
		}
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM release_approvals WHERE release_id::text = $1 AND decision = 'approve'`, id).Scan(&n); err != nil {
		return 0, err
	}
	return n, tx.Commit(ctx)
}

// SetReleaseMerge records the merge of a release's pull request (or why it failed).
func (s *Store) SetReleaseMerge(ctx context.Context, id, sha, errMsg string) error {
	_, err := s.db.Exec(ctx, `UPDATE releases SET merge_sha = NULLIF($2, ''), merge_error = NULLIF($3, '') WHERE id = $1`, id, sha, errMsg)
	return err
}

// PRReleases lists the releases of one pull request, newest first.
func (s *Store) PRReleases(ctx context.Context, kind string, pr int) ([]*Release, error) {
	rows, err := s.db.Query(ctx, `SELECT `+relCols+` FROM releases WHERE kind = $1 AND pr_number = $2 ORDER BY number DESC`, kind, pr)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRelease)
}

func (s *Store) withApprovals(ctx context.Context, rels []*Release) error {
	if len(rels) == 0 {
		return nil
	}
	ids := make([]string, len(rels))
	by := map[string]*Release{}
	for i, r := range rels {
		ids[i] = r.ID
		r.Approvals = []ReleaseApproval{}
		by[r.ID] = r
	}
	rows, err := s.db.Query(ctx, `SELECT release_id::text, approver, decision, reason, created_at FROM release_approvals
		WHERE release_id::text = ANY($1) ORDER BY created_at`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var a ReleaseApproval
		if err := rows.Scan(&id, &a.Approver, &a.Decision, &a.Reason, &a.CreatedAt); err != nil {
			return err
		}
		by[id].Approvals = append(by[id].Approvals, a)
	}
	return rows.Err()
}

// FinishRelease stores a build's outcome. A ready release carries its bundle
// (inline, or the bucket key holding it) and its manifest.
func (s *Store) FinishRelease(ctx context.Context, id, status string, checks, manifest []byte, sha string, size int64, bundle []byte, object, errMsg string) error {
	if status == "failed" {
		object, bundle = "", nil
	}
	var man any
	if manifest != nil {
		man = string(manifest)
	}
	_, err := s.db.Exec(ctx, `UPDATE releases SET status = $2, checks = $3, manifest = $4::jsonb, sha256 = NULLIF($5, ''), size = $6,
		bundle = $7, object = NULLIF($8, ''), error = NULLIF($9, ''), finished_at = now() WHERE id = $1 AND status = 'building'`,
		id, status, string(checks), man, sha, size, bundle, object, errMsg)
	return err
}

// FailInterruptedBuilds marks builds that cannot still be running (the plane restarted).
func (s *Store) FailInterruptedBuilds(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.Exec(ctx, `UPDATE releases SET status = 'failed', error = 'the build was interrupted', finished_at = now()
		WHERE status = 'building' AND created_at < now() - $1::interval`, olderThan.String())
	return err
}

func (s *Store) ListReleases(ctx context.Context, kind string, limit int) ([]*Release, error) {
	rows, err := s.db.Query(ctx, `SELECT `+relCols+` FROM releases WHERE kind = $1 ORDER BY number DESC LIMIT $2`, kind, limit)
	if err != nil {
		return nil, err
	}
	rels, err := Collect(rows, scanRelease)
	if err == nil {
		err = s.withApprovals(ctx, rels)
	}
	return rels, err
}

// GetRelease returns a release with its manifest (never its bundle).
func (s *Store) GetRelease(ctx context.Context, id string) (*Release, error) {
	var man *string
	r, err := scanReleaseWith(s.db.QueryRow(ctx, `SELECT `+relCols+`, manifest::text FROM releases WHERE id::text = $1`, id), &man)
	if err == nil && man != nil {
		r.Manifest = json.RawMessage(*man)
	}
	if err == nil {
		err = s.withApprovals(ctx, []*Release{r})
	}
	return r, err
}

// ActiveRelease is the deployed release of a kind, with its manifest.
func (s *Store) ActiveRelease(ctx context.Context, kind string) (*Release, error) {
	var man *string
	r, err := scanReleaseWith(s.db.QueryRow(ctx, `SELECT `+relCols+`, manifest::text FROM releases WHERE kind = $1 AND status = 'active'`, kind), &man)
	if err == nil && man != nil {
		r.Manifest = json.RawMessage(*man)
	}
	return r, err
}

func scanReleaseWith(r pgx.Row, man **string) (*Release, error) {
	var x Release
	var checks string
	dest := []any{&x.ID, &x.Kind, &x.Number, &x.Revision, &x.Status, &checks, &x.SHA256, &x.Size, &x.Error,
		&x.CreatedBy, &x.CreatedAt, &x.FinishedAt, &x.DeployedBy, &x.DeployedAt,
		&x.Origin, &x.Ref, &x.PRNumber, &x.PRURL, &x.Title, &x.RequestedBy, &x.RequestedAt, &x.MergeSHA, &x.MergeError}
	if man != nil {
		dest = append(dest, man)
	}
	err := r.Scan(dest...)
	x.Checks = json.RawMessage(checks)
	return &x, NotFound(err)
}

// ReleaseBundle returns a bundle by checksum: inline bytes, or the bucket key.
func (s *Store) ReleaseBundle(ctx context.Context, sha string) (bundle []byte, object string, err error) {
	var obj *string
	err = s.db.QueryRow(ctx, `SELECT bundle, object FROM releases WHERE sha256 = $1 AND status IN ('ready', 'pending', 'active', 'superseded') LIMIT 1`, sha).Scan(&bundle, &obj)
	if obj != nil {
		object = *obj
	}
	return bundle, object, NotFound(err)
}

// ReleasePolicySet is a policy set as a policy release deploys it.
type ReleasePolicySet struct {
	Name, Scope, Level, Module string
}

// DeployRelease makes a built release the active one of its kind; the
// previous active release is superseded (and can be deployed again, which
// is how rollback works). Deploying a policy release replaces the policy
// sets of the previous release in the same transaction.
func (s *Store) DeployRelease(ctx context.Context, id, by string, sets []ReleasePolicySet) (*Release, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var kind, status string
	if err := tx.QueryRow(ctx, `SELECT kind, status FROM releases WHERE id::text = $1 FOR UPDATE`, id).Scan(&kind, &status); err != nil {
		return nil, NotFound(err)
	}
	if status != "ready" && status != "superseded" && status != "active" && status != "pending" {
		return nil, errors.New("only a successfully built release can be deployed")
	}
	if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'superseded' WHERE kind = $1 AND status = 'active' AND id::text <> $2`, kind, id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'active', deployed_by = $2, deployed_at = now(), requested_by = NULL, requested_at = NULL WHERE id::text = $1`, id, by); err != nil {
		return nil, err
	}
	if kind == "policies" {
		if _, err := tx.Exec(ctx, `DELETE FROM policy_sets WHERE source = 'release'`); err != nil {
			return nil, err
		}
		for _, p := range sets {
			if _, err := tx.Exec(ctx, `INSERT INTO policy_sets (name, scope, level, module, enabled, source, created_by, updated_by)
				VALUES ($1, $2, $3, $4, true, 'release', $5, $5)`, p.Name, p.Scope, p.Level, p.Module, by); err != nil {
				if IsUnique(err) {
					return nil, ErrConflict
				}
				return nil, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetRelease(ctx, id)
}

// ConsolePolicyNames are names a policy release may not take.
func (s *Store) ConsolePolicyNames(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.Query(ctx, `SELECT name FROM policy_sets WHERE source = 'console'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = true
	}
	return out, rows.Err()
}
