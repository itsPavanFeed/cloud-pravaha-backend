-- Central plane schema: identity and the tenant directory. No infrastructure
-- data lives here; stacks, runs and state stay in each tenant's own plane.

CREATE TABLE schema_meta (
    key   text PRIMARY KEY,
    value bytea NOT NULL
);

CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email          text NOT NULL UNIQUE,
    name           text NOT NULL DEFAULT '',
    platform_admin boolean NOT NULL DEFAULT false,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    disabled_at    timestamptz
);

-- Bearer tokens. Only SHA-256 hashes are stored.
CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users(id),
    name         text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    created_by   text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz
);

-- Onboarded tenants and where their tenant plane runs.
CREATE TABLE tenants (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          text NOT NULL UNIQUE,
    name          text NOT NULL,
    backend_url   text NOT NULL,
    server_ca_pem text NOT NULL DEFAULT '',  -- CA for the tenant plane's TLS certificate ('' = system roots)
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Business units / teams inside a tenant.
CREATE TABLE entities (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    slug       text NOT NULL,
    name       text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

-- A role held by a user, either tenant-wide (entity_id NULL) or in one entity.
CREATE TABLE memberships (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    uuid NOT NULL REFERENCES users(id),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    entity_id  uuid REFERENCES entities(id),
    role       text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK ((entity_id IS NULL AND role IN ('tenant_admin', 'finops', 'security', 'auditor'))
        OR (entity_id IS NOT NULL AND role IN ('admin', 'manager', 'developer', 'viewer'))),
    UNIQUE NULLS NOT DISTINCT (user_id, tenant_id, entity_id, role)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

-- Hash-chained audit log; `entity` holds the tenant slug for tenant-scoped events.
CREATE TABLE audit_events (
    id        bigserial PRIMARY KEY,
    ts        timestamptz NOT NULL,
    actor     text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL,
    entity    text NOT NULL DEFAULT '',
    payload   json NOT NULL,
    prev_hash text NOT NULL,
    hash      text NOT NULL UNIQUE
);

CREATE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END $$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();
