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
}

const relCols = `id, kind, number, revision, status, checks, COALESCE(sha256, ''), COALESCE(size, 0), COALESCE(error, ''),
	created_by, created_at, finished_at, COALESCE(deployed_by, ''), deployed_at`

func scanRelease(r pgx.Row) (*Release, error) {
	var x Release
	var checks string
	err := r.Scan(&x.ID, &x.Kind, &x.Number, &x.Revision, &x.Status, &checks, &x.SHA256, &x.Size, &x.Error,
		&x.CreatedBy, &x.CreatedAt, &x.FinishedAt, &x.DeployedBy, &x.DeployedAt)
	x.Checks = json.RawMessage(checks)
	return &x, NotFound(err)
}

// StartRelease records a new build. Only one build of a kind runs at a time.
func (s *Store) StartRelease(ctx context.Context, kind, revision, by string) (*Release, error) {
	r, err := scanRelease(s.db.QueryRow(ctx, `INSERT INTO releases (kind, number, revision, status, created_by)
		VALUES ($1, COALESCE((SELECT max(number) FROM releases WHERE kind = $1), 0) + 1, $2, 'building', $3)
		RETURNING `+relCols, kind, revision, by))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return r, err
}

// FinishRelease stores a build's outcome. A ready release carries its bundle
// (inline, or the bucket key holding it) and its manifest.
func (s *Store) FinishRelease(ctx context.Context, id, status string, checks, manifest []byte, sha string, size int64, bundle []byte, object, errMsg string) error {
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
	return Collect(rows, scanRelease)
}

// GetRelease returns a release with its manifest (never its bundle).
func (s *Store) GetRelease(ctx context.Context, id string) (*Release, error) {
	var man *string
	r, err := scanReleaseWith(s.db.QueryRow(ctx, `SELECT `+relCols+`, manifest::text FROM releases WHERE id::text = $1`, id), &man)
	if err == nil && man != nil {
		r.Manifest = json.RawMessage(*man)
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
	err := r.Scan(&x.ID, &x.Kind, &x.Number, &x.Revision, &x.Status, &checks, &x.SHA256, &x.Size, &x.Error,
		&x.CreatedBy, &x.CreatedAt, &x.FinishedAt, &x.DeployedBy, &x.DeployedAt, man)
	x.Checks = json.RawMessage(checks)
	return &x, NotFound(err)
}

// ReleaseBundle returns a bundle by checksum: inline bytes, or the bucket key.
func (s *Store) ReleaseBundle(ctx context.Context, sha string) (bundle []byte, object string, err error) {
	var obj *string
	err = s.db.QueryRow(ctx, `SELECT bundle, object FROM releases WHERE sha256 = $1 AND status IN ('ready', 'active', 'superseded') LIMIT 1`, sha).Scan(&bundle, &obj)
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
	if status != "ready" && status != "superseded" && status != "active" {
		return nil, errors.New("only a successfully built release can be deployed")
	}
	if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'superseded' WHERE kind = $1 AND status = 'active' AND id::text <> $2`, kind, id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE releases SET status = 'active', deployed_by = $2, deployed_at = now() WHERE id::text = $1`, id, by); err != nil {
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
