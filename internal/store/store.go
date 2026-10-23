// Package store is the PostgreSQL persistence layer. Store is a tenant plane's
// database: cloud connections, environments, stacks, runs, approvals, state and
// the audit log of one tenant. Rows are scoped to a business unit (BU) and also
// record the BU's entity.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

type Store struct{ Base }

func Open(ctx context.Context, url string) (*Store, error) {
	db, err := Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Store{Base{db: db, scopeCol: "bu"}}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	sub, _ := fs.Sub(migrations, "migrations")
	return Migrate(ctx, s.db, sub)
}

// buFilter returns a SQL condition on col for a visible-BUs list (nil = all).
func buFilter(col string, bus []string, args *[]any) string {
	if bus == nil {
		return "true"
	}
	*args = append(*args, bus)
	return fmt.Sprintf("%s = ANY($%d)", col, len(*args))
}

// ---- runners (tenant-wide) ----

type Runner struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Pool       string     `json:"pool"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

const runnerCols = `id, name, pool, created_at, last_seen_at, revoked_at`

func scanRunner(r pgx.Row) (*Runner, error) {
	var x Runner
	err := r.Scan(&x.ID, &x.Name, &x.Pool, &x.CreatedAt, &x.LastSeenAt, &x.RevokedAt)
	return &x, NotFound(err)
}

func (s *Store) CreateRunner(ctx context.Context, name, pool string, hash []byte) (*Runner, error) {
	r, err := scanRunner(s.db.QueryRow(ctx, `INSERT INTO runners (name, pool, token_hash) VALUES ($1, $2, $3) RETURNING `+runnerCols, name, pool, hash))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return r, err
}

func (s *Store) RunnerByHash(ctx context.Context, hash []byte) (*Runner, error) {
	return scanRunner(s.db.QueryRow(ctx, `UPDATE runners SET last_seen_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL RETURNING `+runnerCols, hash))
}

func (s *Store) ListRunners(ctx context.Context) ([]*Runner, error) {
	rows, err := s.db.Query(ctx, `SELECT `+runnerCols+` FROM runners ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRunner)
}

func (s *Store) RevokeRunner(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE runners SET revoked_at = now() WHERE id::text = $1 AND revoked_at IS NULL`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- cloud connections (tenant-wide) ----

// Connection is a cloud account, project or subscription registered once per
// tenant. It holds identifiers only; Entities limits which entities may use it.
type Connection struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Cloud     json.RawMessage `json:"cloud"`
	Entities  []string        `json:"entities"` // empty = every entity
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

const connCols = `id, name, cloud, entities, created_by, created_at, updated_at`

func scanConn(r pgx.Row) (*Connection, error) {
	var c Connection
	err := r.Scan(&c.ID, &c.Name, &c.Cloud, &c.Entities, &c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if c.Entities == nil {
		c.Entities = []string{}
	}
	return &c, NotFound(err)
}

// Allows reports whether an entity may use the connection.
func (c *Connection) Allows(entity string) bool {
	if len(c.Entities) == 0 {
		return true
	}
	return containsStr(c.Entities, entity)
}

func (s *Store) CreateConnection(ctx context.Context, c *Connection) (*Connection, error) {
	out, err := scanConn(s.db.QueryRow(ctx, `INSERT INTO cloud_connections (name, cloud, entities, created_by) VALUES ($1, $2, $3, $4) RETURNING `+connCols,
		c.Name, c.Cloud, c.Entities, c.CreatedBy))
	if IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

func (s *Store) UpdateConnection(ctx context.Context, c *Connection) (*Connection, error) {
	return scanConn(s.db.QueryRow(ctx, `UPDATE cloud_connections SET cloud = $2, entities = $3, updated_at = now() WHERE id = $1 RETURNING `+connCols,
		c.ID, c.Cloud, c.Entities))
}

func (s *Store) GetConnection(ctx context.Context, idOrName string) (*Connection, error) {
	return scanConn(s.db.QueryRow(ctx, `SELECT `+connCols+` FROM cloud_connections WHERE id::text = $1 OR name = $1`, idOrName))
}

func (s *Store) ListConnections(ctx context.Context) ([]*Connection, error) {
	rows, err := s.db.Query(ctx, `SELECT `+connCols+` FROM cloud_connections ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanConn)
}

// ---- environments ----

// Environment is a deployment target inside a BU: a cloud connection (or none)
// plus a tier and guardrails. Cloud is read from the connection.
type Environment struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	BU           string          `json:"bu"`
	Entity       string          `json:"entity"`
	Tier         string          `json:"tier"`
	ConnectionID *string         `json:"connection_id,omitempty"`
	Connection   string          `json:"connection,omitempty"`
	Cloud        json.RawMessage `json:"cloud"`
	RunnerPool   string          `json:"runner_pool"`
	MaxDestroys  int             `json:"max_destroys"`
	AllowDestroy bool            `json:"allow_destroy"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
}

const envSelect = `SELECT e.id, e.name, e.bu, e.entity, e.tier, e.connection_id, COALESCE(c.name, ''),
	COALESCE(c.cloud, '{"provider":"none"}'::jsonb), e.runner_pool, e.max_destroys, e.allow_destroy, e.created_by, e.created_at, e.updated_at
	FROM environments e LEFT JOIN cloud_connections c ON c.id = e.connection_id`

func scanEnv(r pgx.Row) (*Environment, error) {
	var e Environment
	err := r.Scan(&e.ID, &e.Name, &e.BU, &e.Entity, &e.Tier, &e.ConnectionID, &e.Connection, &e.Cloud, &e.RunnerPool, &e.MaxDestroys, &e.AllowDestroy, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)
	return &e, NotFound(err)
}

func (s *Store) CreateEnvironment(ctx context.Context, e *Environment) (*Environment, error) {
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO environments (name, bu, entity, tier, connection_id, runner_pool, max_destroys, allow_destroy, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`, e.Name, e.BU, e.Entity, e.Tier, e.ConnectionID, e.RunnerPool, e.MaxDestroys, e.AllowDestroy, e.CreatedBy).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetEnvironment(ctx, id)
}

func (s *Store) UpdateEnvironment(ctx context.Context, e *Environment) (*Environment, error) {
	tag, err := s.db.Exec(ctx, `UPDATE environments SET tier = $2, connection_id = $3, runner_pool = $4, max_destroys = $5, allow_destroy = $6, updated_at = now()
		WHERE id = $1`, e.ID, e.Tier, e.ConnectionID, e.RunnerPool, e.MaxDestroys, e.AllowDestroy)
	if err == nil && tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return s.GetEnvironment(ctx, e.ID)
}

func (s *Store) GetEnvironment(ctx context.Context, idOrName string) (*Environment, error) {
	return scanEnv(s.db.QueryRow(ctx, envSelect+` WHERE e.id::text = $1 OR e.name = $1`, idOrName))
}

func (s *Store) ListEnvironments(ctx context.Context, bus []string) ([]*Environment, error) {
	args := []any{}
	rows, err := s.db.Query(ctx, envSelect+` WHERE `+buFilter("e.bu", bus, &args)+` ORDER BY e.entity, e.bu, e.name`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanEnv)
}

// ---- stacks ----

type Stack struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	BU            string          `json:"bu"`
	Entity        string          `json:"entity"`
	EnvironmentID string          `json:"environment_id"`
	Environment   string          `json:"environment"`
	Spec          json.RawMessage `json:"spec"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	LastRun       *RunBrief       `json:"last_run,omitempty"`
	Drift         DriftSettings   `json:"drift"`
}

type DriftSettings struct {
	IntervalMinutes int        `json:"interval_minutes"` // 0 = no scheduled checks
	AutoRemediate   bool       `json:"auto_remediate"`   // queue a corrective plan (still approved) when drift is found
	LastCheck       *time.Time `json:"last_check,omitempty"`
}

type RunBrief struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Operation string    `json:"operation"`
	CreatedAt time.Time `json:"created_at"`
}

const stackSelect = `SELECT s.id, s.name, s.bu, s.entity, s.environment_id, e.name, s.spec, s.created_by, s.created_at, s.updated_at,
	s.drift_interval_minutes, s.drift_auto_remediate, s.last_drift_check,
	lr.id, lr.status, lr.operation, lr.created_at
	FROM stacks s JOIN environments e ON e.id = s.environment_id
	LEFT JOIN LATERAL (SELECT id, status, operation, created_at FROM runs WHERE stack_id = s.id ORDER BY created_at DESC LIMIT 1) lr ON true`

func scanStack(r pgx.Row) (*Stack, error) {
	var x Stack
	var rid, rstatus, rop *string
	var rat *time.Time
	err := r.Scan(&x.ID, &x.Name, &x.BU, &x.Entity, &x.EnvironmentID, &x.Environment, &x.Spec, &x.CreatedBy, &x.CreatedAt, &x.UpdatedAt,
		&x.Drift.IntervalMinutes, &x.Drift.AutoRemediate, &x.Drift.LastCheck, &rid, &rstatus, &rop, &rat)
	if rid != nil {
		x.LastRun = &RunBrief{ID: *rid, Status: *rstatus, Operation: *rop, CreatedAt: *rat}
	}
	return &x, NotFound(err)
}

func (s *Store) CreateStack(ctx context.Context, name, bu, entity, envID string, spec []byte, by string) (*Stack, error) {
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO stacks (name, bu, entity, environment_id, spec, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		name, bu, entity, envID, spec, by).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return s.GetStack(ctx, id)
}

// UpdateStack replaces a stack's spec. It fails while a run is active, so a
// plan can never be applied against a spec it was not made from.
func (s *Store) UpdateStack(ctx context.Context, id string, spec []byte) error {
	tag, err := s.db.Exec(ctx, `UPDATE stacks SET spec = $2, updated_at = now() WHERE id = $1
		AND NOT EXISTS (SELECT 1 FROM runs WHERE stack_id = $1 AND status IN ('queued','planning','planned','apply_queued','applying'))`, id, spec)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (s *Store) GetStack(ctx context.Context, idOrName string) (*Stack, error) {
	return scanStack(s.db.QueryRow(ctx, stackSelect+` WHERE s.id::text = $1 OR s.name = $1`, idOrName))
}

func (s *Store) ListStacks(ctx context.Context, bus []string) ([]*Stack, error) {
	args := []any{}
	rows, err := s.db.Query(ctx, stackSelect+` WHERE `+buFilter("s.bu", bus, &args)+` ORDER BY s.entity, s.bu, s.name`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanStack)
}

func (s *Store) SetDrift(ctx context.Context, stackID string, d DriftSettings) error {
	_, err := s.db.Exec(ctx, `UPDATE stacks SET drift_interval_minutes = $2, drift_auto_remediate = $3 WHERE id = $1`, stackID, d.IntervalMinutes, d.AutoRemediate)
	return err
}

// DueForDrift returns stacks whose scheduled drift check is due and that have
// no active run, marking them checked so concurrent schedulers skip them.
func (s *Store) DueForDrift(ctx context.Context) ([]string, error) {
	rows, err := s.db.Query(ctx, `UPDATE stacks SET last_drift_check = now()
		WHERE drift_interval_minutes > 0
		  AND (last_drift_check IS NULL OR last_drift_check < now() - make_interval(mins => drift_interval_minutes))
		  AND NOT EXISTS (SELECT 1 FROM runs WHERE stack_id = stacks.id AND status IN ('queued','planning','planned','apply_queued','applying'))
		RETURNING id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---- runs ----

type Approval struct {
	Step      string    `json:"step"`
	Approver  string    `json:"approver"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type Run struct {
	ID                string          `json:"id"`
	StackID           string          `json:"stack_id"`
	StackName         string          `json:"stack"`
	BU                string          `json:"bu"`
	Entity            string          `json:"entity"`
	Environment       string          `json:"environment"`
	Operation         string          `json:"operation"`
	Status            string          `json:"status"`
	CreatedBy         string          `json:"created_by"`
	ConfigHash        string          `json:"config_hash"`
	StateSerial       *int64          `json:"state_serial,omitempty"`
	PlanSHA256        *string         `json:"plan_sha256,omitempty"`
	PlanSummary       json.RawMessage `json:"plan_summary,omitempty"`
	PolicyResult      json.RawMessage `json:"policy_result,omitempty"`
	Risk              json.RawMessage `json:"risk,omitempty"`
	Cost              json.RawMessage `json:"cost,omitempty"`
	RequiredApprovals []string        `json:"required_approvals"`
	Approvals         []Approval      `json:"approvals"`
	Error             *string         `json:"error,omitempty"`
	RunnerID          *string         `json:"runner_id,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	PlannedAt         *time.Time      `json:"planned_at,omitempty"`
	FinishedAt        *time.Time      `json:"finished_at,omitempty"`
}

const runSelect = `SELECT r.id, r.stack_id, s.name, s.bu, s.entity, e.name, r.operation, r.status, r.created_by,
	r.config_hash, r.state_serial, r.plan_sha256, r.plan_summary, r.policy_result, r.risk, r.cost, r.required_approvals, r.error, r.runner_id,
	r.created_at, r.updated_at, r.planned_at, r.finished_at,
	COALESCE((SELECT json_agg(json_build_object('step', a.step, 'approver', a.approver, 'reason', a.reason, 'created_at', a.created_at) ORDER BY a.created_at)
	          FROM run_approvals a WHERE a.run_id = r.id), '[]')
	FROM runs r JOIN stacks s ON s.id = r.stack_id JOIN environments e ON e.id = s.environment_id`

func scanRun(r pgx.Row) (*Run, error) {
	var x Run
	var approvals []byte
	err := r.Scan(&x.ID, &x.StackID, &x.StackName, &x.BU, &x.Entity, &x.Environment, &x.Operation, &x.Status, &x.CreatedBy,
		&x.ConfigHash, &x.StateSerial, &x.PlanSHA256, &x.PlanSummary, &x.PolicyResult, &x.Risk, &x.Cost, &x.RequiredApprovals, &x.Error, &x.RunnerID,
		&x.CreatedAt, &x.UpdatedAt, &x.PlannedAt, &x.FinishedAt, &approvals)
	if err == nil {
		json.Unmarshal(approvals, &x.Approvals)
	}
	if x.Approvals == nil {
		x.Approvals = []Approval{}
	}
	if x.RequiredApprovals == nil {
		x.RequiredApprovals = []string{}
	}
	return &x, NotFound(err)
}

// Terminal run statuses.
var Terminal = []string{"no_changes", "policy_failed", "applied", "failed", "discarded", "no_drift", "drifted"}

func (s *Store) CreateRun(ctx context.Context, stackID, op, by, configHash string) (*Run, error) {
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO runs (stack_id, operation, status, created_by, config_hash) VALUES ($1, $2, 'queued', $3, $4) RETURNING id`,
		stackID, op, by, configHash).Scan(&id)
	if IsUnique(err) {
		return nil, ErrConflict // another run holds the stack
	}
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, id)
}

func (s *Store) GetRun(ctx context.Context, id string) (*Run, error) {
	return scanRun(s.db.QueryRow(ctx, runSelect+` WHERE r.id::text = $1`, id))
}

func (s *Store) ListRuns(ctx context.Context, stackID string, bus []string, limit int) ([]*Run, error) {
	args := []any{limit}
	where := buFilter("s.bu", bus, &args)
	if stackID != "" {
		args = append(args, stackID)
		where += fmt.Sprintf(` AND r.stack_id::text = $%d`, len(args))
	}
	rows, err := s.db.Query(ctx, runSelect+` WHERE `+where+` ORDER BY r.created_at DESC LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	return Collect(rows, scanRun)
}

// ClaimRun hands the oldest queued run in a pool to a runner. Plans move
// queued -> planning, approved applies move apply_queued -> applying. The run
// token is replaced on every claim, so a plan-phase token cannot apply.
func (s *Store) ClaimRun(ctx context.Context, runnerID, pool string, tokenHash []byte, ttl time.Duration) (*Run, error) {
	var id string
	err := s.db.QueryRow(ctx, `UPDATE runs SET
			status = CASE status WHEN 'queued' THEN 'planning' ELSE 'applying' END,
			runner_id = $1, run_token_hash = $3, run_token_expires_at = now() + $4::interval, updated_at = now()
		WHERE id = (
			SELECT r.id FROM runs r
			JOIN stacks s ON s.id = r.stack_id JOIN environments e ON e.id = s.environment_id
			WHERE r.status IN ('queued', 'apply_queued') AND e.runner_pool = $2
			ORDER BY r.created_at LIMIT 1 FOR UPDATE OF r SKIP LOCKED)
		RETURNING id`, runnerID, pool, tokenHash, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&id)
	if err != nil {
		return nil, NotFound(err)
	}
	return s.GetRun(ctx, id)
}

// RunByToken resolves a run token to its active run.
func (s *Store) RunByToken(ctx context.Context, hash []byte) (*Run, error) {
	var id string
	err := s.db.QueryRow(ctx, `SELECT id FROM runs WHERE run_token_hash = $1 AND run_token_expires_at > now()
		AND status IN ('planning', 'applying')`, hash).Scan(&id)
	if err != nil {
		return nil, NotFound(err)
	}
	return s.GetRun(ctx, id)
}

func (s *Store) AppendLog(ctx context.Context, runID, chunk string) error {
	_, err := s.db.Exec(ctx, `WITH t AS (UPDATE runs SET updated_at = now() WHERE id = $1)
		INSERT INTO run_logs (run_id, chunk) VALUES ($1, $2)`, runID, chunk)
	return err
}

type LogChunk struct {
	Seq   int64     `json:"seq"`
	TS    time.Time `json:"ts"`
	Chunk string    `json:"chunk"`
}

func (s *Store) Logs(ctx context.Context, runID string, after int64) ([]LogChunk, error) {
	rows, err := s.db.Query(ctx, `SELECT seq, ts, chunk FROM run_logs WHERE run_id::text = $1 AND seq > $2 ORDER BY seq LIMIT 1000`, runID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogChunk{}
	for rows.Next() {
		var c LogChunk
		if err := rows.Scan(&c.Seq, &c.TS, &c.Chunk); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Planned is what a finished plan records.
type Planned struct {
	Status   string // planned | no_changes | policy_failed | no_drift | drifted
	Sealed   []byte
	SHA256   string
	Summary  []byte
	Policy   []byte
	Risk     []byte
	Cost     []byte
	Required []string
	Serial   int64
}

func (s *Store) SetPlanned(ctx context.Context, runID string, p Planned) error {
	terminal := p.Status != "planned"
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = $2, plan_sealed = $3, plan_sha256 = $4, plan_summary = $5, policy_result = $6,
			risk = $7, required_approvals = $8, state_serial = $9, planned_at = now(), updated_at = now(),
			run_token_hash = NULL, run_token_expires_at = NULL,
			finished_at = CASE WHEN $10 THEN now() END, cost = $11
		WHERE id = $1 AND status = 'planning'`, runID, p.Status, p.Sealed, p.SHA256, p.Summary, p.Policy, p.Risk, p.Required, p.Serial, terminal, p.Cost)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (s *Store) PlanBlob(ctx context.Context, runID string) ([]byte, string, error) {
	var b []byte
	var sha *string
	err := s.db.QueryRow(ctx, `SELECT plan_sealed, plan_sha256 FROM runs WHERE id = $1`, runID).Scan(&b, &sha)
	if err != nil || b == nil || sha == nil {
		return nil, "", ErrNotFound
	}
	return b, *sha, nil
}

var (
	ErrNotPlanned      = errors.New("only planned runs can be approved")
	ErrStepNotRequired = errors.New("this run does not need that approval")
	ErrStepDone        = errors.New("that approval step is already signed")
	ErrSelfApproval    = errors.New("separation of duties: the person who started a run cannot approve it")
	ErrTwoSteps        = errors.New("separation of duties: one person may sign only one approval step of a run")
)

// Approve signs one step under a row lock. It returns true when this signature
// completed the chain and the run moved to apply_queued.
func (s *Store) Approve(ctx context.Context, runID, step, approver, reason string) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var status, createdBy string
	var required []string
	if err := tx.QueryRow(ctx, `SELECT status, created_by, required_approvals FROM runs WHERE id = $1 FOR UPDATE`, runID).Scan(&status, &createdBy, &required); err != nil {
		return false, NotFound(err)
	}
	switch {
	case status != "planned":
		return false, ErrNotPlanned
	case createdBy == approver:
		return false, ErrSelfApproval
	case !containsStr(required, step):
		return false, ErrStepNotRequired
	}
	done := map[string]string{}
	rows, err := tx.Query(ctx, `SELECT step, approver FROM run_approvals WHERE run_id = $1`, runID)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var st, by string
		rows.Scan(&st, &by)
		done[st] = by
	}
	rows.Close()
	if _, ok := done[step]; ok {
		return false, ErrStepDone
	}
	for _, by := range done {
		if by == approver {
			return false, ErrTwoSteps
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO run_approvals (run_id, step, approver, reason) VALUES ($1, $2, $3, $4)`, runID, step, approver, reason); err != nil {
		return false, err
	}
	done[step] = approver
	complete := true
	for _, r := range required {
		if _, ok := done[r]; !ok {
			complete = false
		}
	}
	if complete {
		if _, err := tx.Exec(ctx, `UPDATE runs SET status = 'apply_queued', updated_at = now() WHERE id = $1`, runID); err != nil {
			return false, err
		}
	}
	return complete, tx.Commit(ctx)
}

func (s *Store) Discard(ctx context.Context, runID, reason string) error {
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = 'discarded', error = $2, updated_at = now(), finished_at = now(),
		run_token_hash = NULL, plan_sealed = NULL WHERE id::text = $1 AND status IN ('queued', 'planned')`, runID, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// FinishRun ends a run from planning or applying. Saved plans are deleted once
// a run is over: they contain the full proposed state.
func (s *Store) FinishRun(ctx context.Context, runID, status, errMsg string) error {
	var e *string
	if errMsg != "" {
		e = &errMsg
	}
	tag, err := s.db.Exec(ctx, `UPDATE runs SET status = $2, error = $3, updated_at = now(), finished_at = now(),
		run_token_hash = NULL, run_token_expires_at = NULL, plan_sealed = NULL
		WHERE id = $1 AND status IN ('planning', 'applying')`, runID, status, e)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

// Reap fails runs whose runner went silent and discards plans nobody approved in time.
func (s *Store) Reap(ctx context.Context, silentFor, planTTL time.Duration) ([]string, error) {
	rows, err := s.db.Query(ctx, `UPDATE runs SET
			status = CASE WHEN status = 'planned' THEN 'discarded' ELSE 'failed' END,
			error = CASE WHEN status = 'planned' THEN 'plan expired before approval' ELSE 'runner stopped reporting' END,
			finished_at = now(), updated_at = now(), run_token_hash = NULL, plan_sealed = NULL
		WHERE (status IN ('planning', 'applying') AND updated_at < now() - $1::interval)
		   OR (status = 'planned' AND planned_at < now() - $2::interval)
		RETURNING id`, fmt.Sprintf("%d seconds", int(silentFor.Seconds())), fmt.Sprintf("%d seconds", int(planTTL.Seconds())))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// ---- tenant settings ----

// Setting loads a JSON setting into v; it reports false when unset.
func (s *Store) Setting(ctx context.Context, key string, v any) (bool, error) {
	var b []byte
	err := s.db.QueryRow(ctx, `SELECT value FROM tenant_settings WHERE key = $1`, key).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(b, v)
}

func (s *Store) PutSetting(ctx context.Context, key string, v any, by string) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `INSERT INTO tenant_settings (key, value, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_by = $3, updated_at = now()`, key, b, by)
	return err
}

// ---- state (OpenTofu HTTP backend) ----

func (s *Store) CurrentState(ctx context.Context, stackID string) ([]byte, int64, error) {
	var b []byte
	var serial int64
	err := s.db.QueryRow(ctx, `SELECT data, serial FROM state_versions WHERE stack_id = $1 ORDER BY serial DESC LIMIT 1`, stackID).Scan(&b, &serial)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, nil
	}
	return b, serial, err
}

func (s *Store) PutState(ctx context.Context, stackID, runID string, data []byte, sha string) (int64, error) {
	var serial int64
	err := s.db.QueryRow(ctx, `INSERT INTO state_versions (stack_id, serial, data, sha256, run_id)
		SELECT $1, COALESCE(MAX(serial), 0) + 1, $2, $3, $4 FROM state_versions WHERE stack_id = $1 RETURNING serial`,
		stackID, data, sha, runID).Scan(&serial)
	return serial, err
}

type StateVersion struct {
	Serial    int64     `json:"serial"`
	SHA256    string    `json:"sha256"`
	Size      int       `json:"size"`
	RunID     *string   `json:"run_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) StateVersions(ctx context.Context, stackID string) ([]StateVersion, error) {
	rows, err := s.db.Query(ctx, `SELECT serial, sha256, length(data), run_id, created_at FROM state_versions WHERE stack_id = $1 ORDER BY serial DESC LIMIT 100`, stackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StateVersion{}
	for rows.Next() {
		var v StateVersion
		if err := rows.Scan(&v.Serial, &v.SHA256, &v.Size, &v.RunID, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Lock takes the state lock. On conflict it returns the current holder's info.
func (s *Store) Lock(ctx context.Context, stackID, lockID, runID string, info []byte) ([]byte, error) {
	tag, err := s.db.Exec(ctx, `INSERT INTO state_locks (stack_id, lock_id, info, run_id) VALUES ($1, $2, $3, $4) ON CONFLICT (stack_id) DO NOTHING`,
		stackID, lockID, info, runID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 1 {
		return nil, nil
	}
	var cur []byte
	if err := s.db.QueryRow(ctx, `SELECT info FROM state_locks WHERE stack_id = $1`, stackID).Scan(&cur); err != nil {
		return nil, err
	}
	return cur, ErrConflict
}

func (s *Store) Unlock(ctx context.Context, stackID, lockID string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM state_locks WHERE stack_id = $1 AND lock_id = $2`, stackID, lockID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrConflict
	}
	return err
}

func (s *Store) LockHolder(ctx context.Context, stackID string) (lockID string, runID *string, err error) {
	err = s.db.QueryRow(ctx, `SELECT lock_id, run_id FROM state_locks WHERE stack_id = $1`, stackID).Scan(&lockID, &runID)
	return lockID, runID, NotFound(err)
}

// ReleaseRunLocks drops locks left by a run that has ended (crashed runner).
func (s *Store) ReleaseRunLocks(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM state_locks l USING runs r WHERE l.run_id = r.id AND r.status NOT IN ('planning', 'applying')`)
	return err
}

func containsStr(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
