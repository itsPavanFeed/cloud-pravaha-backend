package central

import (
	"context"
	"embed"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/identity"
	"github.com/itsPavanFeed/cloud-pravaha-backend/internal/store"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the central plane's database: users, tokens and the tenant directory.
type Store struct{ store.Base }

func OpenStore(ctx context.Context, url string) (*Store, error) {
	db, err := store.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	return &Store{store.NewBase(db)}, nil
}

func (s *Store) Migrate(ctx context.Context) error {
	sub, _ := fs.Sub(migrations, "migrations")
	return store.Migrate(ctx, s.Pool(), sub)
}

var (
	ErrNotFound = store.ErrNotFound
	ErrConflict = store.ErrConflict
)

// ---- users & tokens ----

type User struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	Name          string     `json:"name"`
	PlatformAdmin bool       `json:"platform_admin"`
	CreatedAt     time.Time  `json:"created_at"`
	DisabledAt    *time.Time `json:"disabled_at,omitempty"`
}

const userCols = `id, email, name, platform_admin, created_at, disabled_at`

func scanUser(r pgx.Row) (*User, error) {
	var u User
	err := r.Scan(&u.ID, &u.Email, &u.Name, &u.PlatformAdmin, &u.CreatedAt, &u.DisabledAt)
	return &u, store.NotFound(err)
}

// EnsureUser returns the user with this email, creating them if needed.
func (s *Store) EnsureUser(ctx context.Context, email, name string, platformAdmin bool, by string) (*User, error) {
	if _, err := s.Pool().Exec(ctx, `INSERT INTO users (email, name, platform_admin, created_by) VALUES ($1, $2, $3, $4) ON CONFLICT (email) DO NOTHING`,
		email, name, platformAdmin, by); err != nil {
		return nil, err
	}
	if platformAdmin {
		if _, err := s.Pool().Exec(ctx, `UPDATE users SET platform_admin = true WHERE email = $1`, email); err != nil {
			return nil, err
		}
	}
	return s.UserByEmail(ctx, email)
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.Pool().QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

func (s *Store) CreateToken(ctx context.Context, userID, name, by string, hash []byte, expires time.Time) (*Token, error) {
	var t Token
	err := s.Pool().QueryRow(ctx, `INSERT INTO api_tokens (user_id, name, token_hash, created_by, expires_at) VALUES ($1, $2, $3, $4, $5)
		RETURNING id, name, created_by, created_at, expires_at, last_used_at, revoked_at`, userID, name, hash, by, expires).
		Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	return &t, err
}

// UserByToken resolves a valid token to an enabled user and records its use.
func (s *Store) UserByToken(ctx context.Context, hash []byte) (*User, error) {
	return scanUser(s.Pool().QueryRow(ctx, `WITH t AS (
			UPDATE api_tokens SET last_used_at = now()
			WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now() RETURNING user_id)
		SELECT `+userCols+` FROM users WHERE id = (SELECT user_id FROM t) AND disabled_at IS NULL`, hash))
}

func (s *Store) ListTokens(ctx context.Context, userID string) ([]*Token, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, name, created_by, created_at, expires_at, last_used_at, revoked_at FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, func(r pgx.Row) (*Token, error) {
		var t Token
		return &t, r.Scan(&t.ID, &t.Name, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	})
}

func (s *Store) RevokeToken(ctx context.Context, userID, id string) error {
	tag, err := s.Pool().Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id::text = $1 AND user_id = $2 AND revoked_at IS NULL`, id, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- tenants & entities ----

type Tenant struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	BackendURL  string    `json:"backend_url"`
	ServerCAPEM string    `json:"server_ca_pem,omitempty"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const tenantCols = `id, slug, name, backend_url, server_ca_pem, created_by, created_at, updated_at`

func scanTenant(r pgx.Row) (*Tenant, error) {
	var t Tenant
	err := r.Scan(&t.ID, &t.Slug, &t.Name, &t.BackendURL, &t.ServerCAPEM, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt)
	return &t, store.NotFound(err)
}

func (s *Store) CreateTenant(ctx context.Context, t *Tenant) (*Tenant, error) {
	out, err := scanTenant(s.Pool().QueryRow(ctx, `INSERT INTO tenants (slug, name, backend_url, server_ca_pem, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING `+tenantCols,
		t.Slug, t.Name, t.BackendURL, t.ServerCAPEM, t.CreatedBy))
	if store.IsUnique(err) {
		return nil, ErrConflict
	}
	return out, err
}

func (s *Store) UpdateTenant(ctx context.Context, t *Tenant) (*Tenant, error) {
	return scanTenant(s.Pool().QueryRow(ctx, `UPDATE tenants SET name = $2, backend_url = $3, server_ca_pem = $4, updated_at = now() WHERE slug = $1 RETURNING `+tenantCols,
		t.Slug, t.Name, t.BackendURL, t.ServerCAPEM))
}

func (s *Store) Tenant(ctx context.Context, slug string) (*Tenant, error) {
	return scanTenant(s.Pool().QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug = $1`, slug))
}

func (s *Store) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY slug`)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanTenant)
}

type Entity struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func scanEntity(r pgx.Row) (*Entity, error) {
	var e Entity
	err := r.Scan(&e.ID, &e.Slug, &e.Name, &e.CreatedBy, &e.CreatedAt)
	return &e, store.NotFound(err)
}

func (s *Store) CreateEntity(ctx context.Context, tenantID, slug, name, by string) (*Entity, error) {
	e, err := scanEntity(s.Pool().QueryRow(ctx, `INSERT INTO entities (tenant_id, slug, name, created_by) VALUES ($1, $2, $3, $4)
		RETURNING id, slug, name, created_by, created_at`, tenantID, slug, name, by))
	if store.IsUnique(err) {
		return nil, ErrConflict
	}
	return e, err
}

func (s *Store) Entities(ctx context.Context, tenantID string) ([]*Entity, error) {
	rows, err := s.Pool().Query(ctx, `SELECT id, slug, name, created_by, created_at FROM entities WHERE tenant_id = $1 ORDER BY slug`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanEntity)
}

func (s *Store) Entity(ctx context.Context, tenantID, slug string) (*Entity, error) {
	return scanEntity(s.Pool().QueryRow(ctx, `SELECT id, slug, name, created_by, created_at FROM entities WHERE tenant_id = $1 AND slug = $2`, tenantID, slug))
}

// ---- memberships ----

type Membership struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Tenant    string    `json:"tenant"`
	Entity    string    `json:"entity,omitempty"` // '' = tenant-wide role
	Role      string    `json:"role"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

const memberSelect = `SELECT m.id, u.email, t.slug, COALESCE(e.slug, ''), m.role, m.created_by, m.created_at
	FROM memberships m JOIN users u ON u.id = m.user_id JOIN tenants t ON t.id = m.tenant_id
	LEFT JOIN entities e ON e.id = m.entity_id`

func scanMember(r pgx.Row) (*Membership, error) {
	var m Membership
	err := r.Scan(&m.ID, &m.Email, &m.Tenant, &m.Entity, &m.Role, &m.CreatedBy, &m.CreatedAt)
	return &m, store.NotFound(err)
}

func (s *Store) AddMembership(ctx context.Context, userID, tenantID string, entityID *string, role, by string) (*Membership, error) {
	var id string
	err := s.Pool().QueryRow(ctx, `INSERT INTO memberships (user_id, tenant_id, entity_id, role, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		userID, tenantID, entityID, role, by).Scan(&id)
	if store.IsUnique(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return scanMember(s.Pool().QueryRow(ctx, memberSelect+` WHERE m.id = $1`, id))
}

func (s *Store) RemoveMembership(ctx context.Context, tenantID, id string) (*Membership, error) {
	m, err := scanMember(s.Pool().QueryRow(ctx, memberSelect+` WHERE m.id::text = $1 AND m.tenant_id = $2`, id, tenantID))
	if err != nil {
		return nil, err
	}
	_, err = s.Pool().Exec(ctx, `DELETE FROM memberships WHERE id = $1`, m.ID)
	return m, err
}

func (s *Store) TenantMembers(ctx context.Context, tenantID string) ([]*Membership, error) {
	rows, err := s.Pool().Query(ctx, memberSelect+` WHERE m.tenant_id = $1 ORDER BY u.email, e.slug NULLS FIRST, m.role`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanMember)
}

// Principal builds a user's roles inside one tenant (nil if they have none).
func (s *Store) Principal(ctx context.Context, u *User, tenantSlug string) (*identity.Principal, error) {
	rows, err := s.Pool().Query(ctx, memberSelect+` WHERE m.user_id = $1 AND t.slug = $2`, u.ID, tenantSlug)
	if err != nil {
		return nil, err
	}
	ms, err := store.Collect(rows, scanMember)
	if err != nil {
		return nil, err
	}
	if len(ms) == 0 && !u.PlatformAdmin {
		return nil, nil
	}
	p := &identity.Principal{Subject: u.Email, Tenant: tenantSlug, TenantRoles: []string{}, EntityRoles: map[string][]string{}, PlatformAdmin: u.PlatformAdmin}
	for _, m := range ms {
		if m.Entity == "" {
			p.TenantRoles = append(p.TenantRoles, m.Role)
		} else {
			p.EntityRoles[m.Entity] = append(p.EntityRoles[m.Entity], m.Role)
		}
	}
	return p, nil
}

// UserTenants lists slugs of tenants where the user has any role.
func (s *Store) UserTenants(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.Pool().Query(ctx, `SELECT DISTINCT t.slug FROM memberships m JOIN tenants t ON t.id = m.tenant_id WHERE m.user_id = $1 ORDER BY 1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		out = append(out, s)
	}
	return out, rows.Err()
}

// OnlyInTenant reports whether every membership of the user is inside tenantID,
// so a tenant admin can never mint tokens for someone who belongs elsewhere.
func (s *Store) OnlyInTenant(ctx context.Context, userID, tenantID string) (bool, error) {
	var other bool
	err := s.Pool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM memberships WHERE user_id = $1 AND tenant_id <> $2)`, userID, tenantID).Scan(&other)
	return !other, err
}
