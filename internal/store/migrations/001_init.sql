-- Cloud Pravaha schema v1.

CREATE TABLE schema_meta (
    key   text PRIMARY KEY,
    value bytea NOT NULL
);

-- Tenant plane schema. People are authenticated by the central plane, which
-- forwards each request with a signed assertion; this database stores no users.
-- Every stack, environment, run and audit event belongs to an entity (business unit).

-- Runner agents. A runner serves exactly one pool.
CREATE TABLE runners (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    pool        text NOT NULL,
    token_hash  bytea NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz,
    revoked_at  timestamptz
);

-- Environments carry the cloud integration (identifiers only) and guardrails.
CREATE TABLE environments (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    entity        text NOT NULL,
    tier          text NOT NULL CHECK (tier IN ('prod', 'nonprod')),
    cloud         jsonb NOT NULL,
    runner_pool   text NOT NULL,
    max_destroys  integer NOT NULL DEFAULT 0 CHECK (max_destroys >= 0),
    allow_destroy boolean NOT NULL DEFAULT false,
    created_by    text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE stacks (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name           text NOT NULL UNIQUE,
    entity         text NOT NULL,
    environment_id uuid NOT NULL REFERENCES environments(id),
    spec           jsonb NOT NULL,
    created_by     text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

-- One run = one plan and, after approval, its apply.
-- queued -> planning -> planned | no_changes | policy_failed | failed
-- planned -> (every required approval) apply_queued -> applying -> applied | failed
-- planned -> discarded (manually or when it goes stale / expires)
CREATE TABLE runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    stack_id        uuid NOT NULL REFERENCES stacks(id),
    operation       text NOT NULL CHECK (operation IN ('apply', 'destroy')),
    status          text NOT NULL,
    created_by      text NOT NULL,
    risk            jsonb,                  -- level, reasons, required approvals
    required_approvals text[] NOT NULL DEFAULT '{}',
    config_hash     text NOT NULL,          -- generated config the plan was made from
    state_serial    bigint,                 -- state version the plan was made against
    plan_sealed     bytea,                  -- saved plan, OpenTofu-encrypted then AES-GCM sealed
    plan_sha256     text,
    plan_summary    jsonb,
    policy_result   jsonb,
    error           text,
    runner_id       uuid REFERENCES runners(id),
    run_token_hash  bytea UNIQUE,           -- scopes the runner to this run's state and plan
    run_token_expires_at timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    planned_at      timestamptz,
    finished_at     timestamptz
);
CREATE INDEX stacks_entity_idx ON stacks (entity);
CREATE INDEX runs_stack_idx ON runs (stack_id, created_at DESC);
CREATE INDEX runs_queue_idx ON runs (status, created_at) WHERE status IN ('queued', 'apply_queued');
-- At most one active run per stack: the stack lock.
CREATE UNIQUE INDEX runs_one_active_per_stack ON runs (stack_id)
    WHERE status IN ('queued', 'planning', 'planned', 'apply_queued', 'applying');

-- One row per approval step (manager, finops, security). A person signs at most
-- one step of a run, and never a run they started (enforced in the store).
CREATE TABLE run_approvals (
    run_id     uuid NOT NULL REFERENCES runs(id),
    step       text NOT NULL CHECK (step IN ('manager', 'finops', 'security')),
    approver   text NOT NULL,
    reason     text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, step),
    UNIQUE (run_id, approver)
);

CREATE TABLE run_logs (
    run_id  uuid NOT NULL REFERENCES runs(id),
    seq     bigserial,
    ts      timestamptz NOT NULL DEFAULT now(),
    chunk   text NOT NULL,
    PRIMARY KEY (run_id, seq)
);

-- OpenTofu HTTP backend storage. State is client-side encrypted by OpenTofu on
-- the runner, so the control plane only ever holds ciphertext.
CREATE TABLE state_versions (
    stack_id   uuid NOT NULL REFERENCES stacks(id),
    serial     bigint NOT NULL,
    data       bytea NOT NULL,
    sha256     text NOT NULL,
    run_id     uuid REFERENCES runs(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stack_id, serial)
);

CREATE TABLE state_locks (
    stack_id   uuid PRIMARY KEY REFERENCES stacks(id),
    lock_id    text NOT NULL,
    info       jsonb NOT NULL,
    run_id     uuid REFERENCES runs(id),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only, hash-chained audit log. `payload` is json (not jsonb) so the
-- exact hashed bytes are preserved.
CREATE TABLE audit_events (
    id        bigserial PRIMARY KEY,
    ts        timestamptz NOT NULL,
    actor     text NOT NULL,
    action    text NOT NULL,
    target    text NOT NULL,
    entity    text NOT NULL DEFAULT '',  -- '' for tenant-wide events
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
