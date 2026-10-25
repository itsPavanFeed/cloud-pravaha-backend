package central

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
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
	// An entity (product) never shares a slug with a business unit, so labels and
	// contract folders are unambiguous.
	e, err := scanEntity(s.Pool().QueryRow(ctx, `INSERT INTO entities (tenant_id, slug, name, created_by)
		SELECT $1, $2, $3, $4 WHERE NOT EXISTS (SELECT 1 FROM business_units WHERE tenant_id = $1 AND slug = $2)
		RETURNING id, slug, name, created_by, created_at`, tenantID, slug, name, by))
	if store.IsUnique(err) || errors.Is(err, store.ErrNotFound) {
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

// ---- business units ----

type BU struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Entity    string    `json:"entity"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

const buSelect = `SELECT b.id, b.slug, b.name, e.slug, b.created_by, b.created_at FROM business_units b JOIN entities e ON e.id = b.entity_id`

func scanBU(r pgx.Row) (*BU, error) {
	var b BU
	err := r.Scan(&b.ID, &b.Slug, &b.Name, &b.Entity, &b.CreatedBy, &b.CreatedAt)
	return &b, store.NotFound(err)
}

func (s *Store) CreateBU(ctx context.Context, tenantID, entityID, slug, name, by string) (*BU, error) {
	var id string
	err := s.Pool().QueryRow(ctx, `INSERT INTO business_units (tenant_id, entity_id, slug, name, created_by)
		SELECT $1, $2, $3, $4, $5 WHERE NOT EXISTS (SELECT 1 FROM entities WHERE tenant_id = $1 AND slug = $3) RETURNING id`,
		tenantID, entityID, slug, name, by).Scan(&id)
	if store.IsUnique(err) || errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return scanBU(s.Pool().QueryRow(ctx, buSelect+` WHERE b.id = $1`, id))
}

func (s *Store) BUs(ctx context.Context, tenantID string) ([]*BU, error) {
	rows, err := s.Pool().Query(ctx, buSelect+` WHERE b.tenant_id = $1 ORDER BY e.slug, b.slug`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanBU)
}

func (s *Store) BUBySlug(ctx context.Context, tenantID, slug string) (*BU, error) {
	return scanBU(s.Pool().QueryRow(ctx, buSelect+` WHERE b.tenant_id = $1 AND b.slug = $2`, tenantID, slug))
}

// ---- memberships ----

type Membership struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Tenant    string    `json:"tenant"`
	Entity    string    `json:"entity,omitempty"` // set for entity-level roles
	BU        string    `json:"bu,omitempty"`     // set for BU-level roles; neither = tenant-wide
	Role      string    `json:"role"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

const memberSelect = `SELECT m.id, u.email, t.slug, COALESCE(e.slug, ''), COALESCE(b.slug, ''), m.role, m.created_by, m.created_at
	FROM memberships m JOIN users u ON u.id = m.user_id JOIN tenants t ON t.id = m.tenant_id
	LEFT JOIN entities e ON e.id = m.entity_id LEFT JOIN business_units b ON b.id = m.bu_id`

func scanMember(r pgx.Row) (*Membership, error) {
	var m Membership
	err := r.Scan(&m.ID, &m.Email, &m.Tenant, &m.Entity, &m.BU, &m.Role, &m.CreatedBy, &m.CreatedAt)
	return &m, store.NotFound(err)
}

func (s *Store) AddMembership(ctx context.Context, userID, tenantID string, entityID, buID *string, role, by string) (*Membership, error) {
	var id string
	err := s.Pool().QueryRow(ctx, `INSERT INTO memberships (user_id, tenant_id, entity_id, bu_id, role, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		userID, tenantID, entityID, buID, role, by).Scan(&id)
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
	rows, err := s.Pool().Query(ctx, memberSelect+` WHERE m.tenant_id = $1 ORDER BY u.email, e.slug NULLS FIRST, b.slug NULLS FIRST, m.role`, tenantID)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanMember)
}

// Principal builds a user's roles inside one tenant (nil if they have none).
// Entity roles are inherited by every BU of the entity: BURoles holds each
// BU's effective roles, which is all tenant planes need to enforce.
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
	t, err := s.Tenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	bus, err := s.BUs(ctx, t.ID)
	if err != nil {
		return nil, err
	}
	p := &identity.Principal{Subject: u.Email, Tenant: tenantSlug, TenantRoles: []string{}, EntityRoles: map[string][]string{},
		BURoles: map[string][]string{}, BUEntity: map[string]string{}, PlatformAdmin: u.PlatformAdmin}
	for _, b := range bus {
		p.BUEntity[b.Slug] = b.Entity
	}
	add := func(m map[string][]string, k, role string) {
		for _, r := range m[k] {
			if r == role {
				return
			}
		}
		m[k] = append(m[k], role)
	}
	for _, m := range ms {
		switch {
		case m.BU != "":
			add(p.BURoles, m.BU, m.Role)
		case m.Entity != "":
			add(p.EntityRoles, m.Entity, m.Role)
		default:
			p.TenantRoles = append(p.TenantRoles, m.Role)
		}
	}
	for _, b := range bus {
		for _, r := range p.EntityRoles[b.Entity] {
			add(p.BURoles, b.Slug, r)
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

// ---- SSO ----

func (s *Store) CreateAuthFlow(ctx context.Context, state, verifier, nonce string) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO auth_flows (state, verifier, nonce) VALUES ($1, $2, $3)`, state, verifier, nonce)
	s.Pool().Exec(ctx, `DELETE FROM auth_flows WHERE created_at < now() - interval '1 hour'`)
	return err
}

// TakeAuthFlow consumes a login flow (single use) if it is younger than ttl.
func (s *Store) TakeAuthFlow(ctx context.Context, state string, ttl time.Duration) (verifier, nonce string, err error) {
	err = s.Pool().QueryRow(ctx, `DELETE FROM auth_flows WHERE state = $1 AND created_at > now() - $2::interval RETURNING verifier, nonce`,
		state, fmt.Sprintf("%d seconds", int(ttl.Seconds()))).Scan(&verifier, &nonce)
	return verifier, nonce, store.NotFound(err)
}

func (s *Store) CreateAuthCode(ctx context.Context, hash []byte, userID string, ttl time.Duration) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO auth_codes (code_hash, user_id, expires_at) VALUES ($1, $2, now() + $3::interval)`,
		hash, userID, fmt.Sprintf("%d seconds", int(ttl.Seconds())))
	s.Pool().Exec(ctx, `DELETE FROM auth_codes WHERE expires_at < now()`)
	return err
}

// TakeAuthCode consumes a one-time sign-in code and returns its (enabled) user.
func (s *Store) TakeAuthCode(ctx context.Context, hash []byte) (*User, error) {
	return scanUser(s.Pool().QueryRow(ctx, `WITH c AS (DELETE FROM auth_codes WHERE code_hash = $1 AND expires_at > now() RETURNING user_id)
		SELECT `+userCols+` FROM users WHERE id = (SELECT user_id FROM c) AND disabled_at IS NULL`, hash))
}

func (s *Store) RevokeTokenByHash(ctx context.Context, hash []byte) error {
	tag, err := s.Pool().Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hash)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ---- SCIM ----

func (s *Store) CreateSCIMToken(ctx context.Context, name, by string, hash []byte) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO scim_tokens (name, token_hash, created_by) VALUES ($1, $2, $3)`, name, hash, by)
	return err
}

func (s *Store) SCIMTokenValid(ctx context.Context, hash []byte) bool {
	var ok bool
	s.Pool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scim_tokens WHERE token_hash = $1 AND revoked_at IS NULL)`, hash).Scan(&ok)
	return ok
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.Pool().QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id::text = $1`, id))
}

func (s *Store) ListUsers(ctx context.Context, limit int) ([]*User, error) {
	rows, err := s.Pool().Query(ctx, `SELECT `+userCols+` FROM users ORDER BY email LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return store.Collect(rows, scanUser)
}

func (s *Store) SetUserName(ctx context.Context, id, name string) error {
	_, err := s.Pool().Exec(ctx, `UPDATE users SET name = $2 WHERE id = $1`, id, name)
	return err
}

// SetUserActive enables or disables a user; disabling revokes all their tokens.
func (s *Store) SetUserActive(ctx context.Context, id string, active bool) error {
	if active {
		_, err := s.Pool().Exec(ctx, `UPDATE users SET disabled_at = NULL WHERE id = $1`, id)
		return err
	}
	if _, err := s.Pool().Exec(ctx, `UPDATE users SET disabled_at = COALESCE(disabled_at, now()) WHERE id = $1`, id); err != nil {
		return err
	}
	_, err := s.Pool().Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, id)
	return err
}

type SCIMGroup struct {
	ID          string
	DisplayName string
}

func (s *Store) CreateSCIMGroup(ctx context.Context, name, externalID string) (*SCIMGroup, error) {
	g := &SCIMGroup{DisplayName: name}
	err := s.Pool().QueryRow(ctx, `INSERT INTO scim_groups (display_name, external_id) VALUES ($1, $2) RETURNING id`, name, externalID).Scan(&g.ID)
	return g, err
}

func (s *Store) SCIMGroupByID(ctx context.Context, id string) (*SCIMGroup, error) {
	g := &SCIMGroup{}
	err := s.Pool().QueryRow(ctx, `SELECT id, display_name FROM scim_groups WHERE id::text = $1`, id).Scan(&g.ID, &g.DisplayName)
	return g, store.NotFound(err)
}

func (s *Store) SCIMGroupByName(ctx context.Context, name string) (*SCIMGroup, error) {
	g := &SCIMGroup{}
	err := s.Pool().QueryRow(ctx, `SELECT id, display_name FROM scim_groups WHERE display_name = $1`, name).Scan(&g.ID, &g.DisplayName)
	return g, store.NotFound(err)
}

func (s *Store) SCIMGroups(ctx context.Context) []*SCIMGroup {
	rows, err := s.Pool().Query(ctx, `SELECT id, display_name FROM scim_groups ORDER BY display_name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []*SCIMGroup
	for rows.Next() {
		g := &SCIMGroup{}
		rows.Scan(&g.ID, &g.DisplayName)
		out = append(out, g)
	}
	return out
}

func (s *Store) DeleteSCIMGroup(ctx context.Context, id string) {
	s.Pool().Exec(ctx, `DELETE FROM scim_groups WHERE id = $1`, id)
}

// SCIMGroupMembers lists users holding a membership granted by the group.
func (s *Store) SCIMGroupMembers(ctx context.Context, groupID string) []*User {
	rows, err := s.Pool().Query(ctx, `SELECT DISTINCT `+prefixCols("u.", userCols)+` FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.created_by = $1`, "scim:"+groupID)
	if err != nil {
		return nil
	}
	us, _ := store.Collect(rows, scanUser)
	return us
}

// RemoveMembershipBy removes one membership created by a given source.
func (s *Store) RemoveMembershipBy(ctx context.Context, userID, tenantID string, entityID, buID *string, role, by string) bool {
	tag, err := s.Pool().Exec(ctx, `DELETE FROM memberships WHERE user_id = $1 AND tenant_id = $2 AND entity_id IS NOT DISTINCT FROM $3
		AND bu_id IS NOT DISTINCT FROM $4 AND role = $5 AND created_by = $6`, userID, tenantID, entityID, buID, role, by)
	return err == nil && tag.RowsAffected() > 0
}

func prefixCols(prefix, cols string) string {
	parts := strings.Split(cols, ", ")
	for i := range parts {
		parts[i] = prefix + parts[i]
	}
	return strings.Join(parts, ", ")
}

// ---- Slack (interactive approvals) ----

type SlackApp struct {
	SigningSecret, BotToken []byte // sealed
	UpdatedBy               string
	UpdatedAt               time.Time
}

func (s *Store) PutSlackApp(ctx context.Context, tenantID string, secret, token []byte, by string) error {
	_, err := s.Pool().Exec(ctx, `INSERT INTO tenant_slack (tenant_id, signing_secret, bot_token, updated_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE SET signing_secret = $2, bot_token = $3, updated_by = $4, updated_at = now()`, tenantID, secret, token, by)
	return err
}

func (s *Store) SlackApp(ctx context.Context, tenantID string) (*SlackApp, error) {
	var a SlackApp
	err := s.Pool().QueryRow(ctx, `SELECT signing_secret, bot_token, updated_by, updated_at FROM tenant_slack WHERE tenant_id = $1`, tenantID).
		Scan(&a.SigningSecret, &a.BotToken, &a.UpdatedBy, &a.UpdatedAt)
	return &a, store.NotFound(err)
}

func (s *Store) DeleteSlackApp(ctx context.Context, tenantID string) error {
	_, err := s.Pool().Exec(ctx, `DELETE FROM tenant_slack WHERE tenant_id = $1`, tenantID)
	return err
}

// Grant is one role of a person in a tenant: tenant-wide, on an entity, or on a BU.
type Grant struct {
	Role     string
	EntityID *string
	BUID     *string
}

// SetUserRoles makes a person's memberships in a tenant exactly grants, in one
// transaction. It returns what was added and removed.
func (s *Store) SetUserRoles(ctx context.Context, tenantID, userID string, grants []Grant, by string) (added, removed []string, err error) {
	tx, err := s.Pool().Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)
	key := func(role string, e, b *string) string {
		d := func(p *string) string {
			if p == nil {
				return ""
			}
			return *p
		}
		return role + "|" + d(e) + "|" + d(b)
	}
	want := map[string]Grant{}
	for _, g := range grants {
		want[key(g.Role, g.EntityID, g.BUID)] = g
	}
	rows, err := tx.Query(ctx, `SELECT id::text, role, entity_id::text, bu_id::text FROM memberships WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`, tenantID, userID)
	if err != nil {
		return nil, nil, err
	}
	have := map[string]string{}
	for rows.Next() {
		var id, role string
		var e, b *string
		if err := rows.Scan(&id, &role, &e, &b); err != nil {
			rows.Close()
			return nil, nil, err
		}
		have[key(role, e, b)] = id
	}
	rows.Close()
	for k, id := range have {
		if _, keep := want[k]; !keep {
			if _, err := tx.Exec(ctx, `DELETE FROM memberships WHERE id = $1`, id); err != nil {
				return nil, nil, err
			}
			removed = append(removed, k)
		}
	}
	for k, g := range want {
		if _, ok := have[k]; ok {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memberships (user_id, tenant_id, entity_id, bu_id, role, created_by) VALUES ($1, $2, $3, $4, $5, $6)`,
			userID, tenantID, g.EntityID, g.BUID, g.Role, by); err != nil {
			return nil, nil, err
		}
		added = append(added, k)
	}
	return added, removed, tx.Commit(ctx)
}
