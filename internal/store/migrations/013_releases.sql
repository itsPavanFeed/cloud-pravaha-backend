-- Module and policy releases built from Git. A release is immutable: its
-- bundle (stored here or in the tenant bucket) is named by its SHA-256, and
-- its manifest carries what deploying it needs (kinds, tenant defaults,
-- policy sets) so a deploy never reads the bundle or the repository.
CREATE TABLE releases (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind        text NOT NULL CHECK (kind IN ('modules', 'policies')),
    number      integer NOT NULL,
    revision    text NOT NULL,
    status      text NOT NULL CHECK (status IN ('building', 'failed', 'ready', 'active', 'superseded')),
    checks      jsonb NOT NULL DEFAULT '[]',
    manifest    jsonb,
    sha256      text,
    size        bigint,
    bundle      bytea,          -- when the tenant has no bucket
    object      text,           -- bucket key otherwise
    error       text,
    created_by  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    deployed_by text,
    deployed_at timestamptz,
    UNIQUE (kind, number)
);
CREATE UNIQUE INDEX releases_one_active ON releases (kind) WHERE status = 'active';
CREATE UNIQUE INDEX releases_one_building ON releases (kind) WHERE status = 'building';

-- Policy sets deployed from a policy release are read-only in the console.
ALTER TABLE policy_sets ADD COLUMN source text NOT NULL DEFAULT 'console' CHECK (source IN ('console', 'release'));
