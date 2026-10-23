-- Tenant-defined Rego policy sets, scoped to the tenant, an entity or a BU.
CREATE TABLE policy_sets (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    scope      text NOT NULL,           -- "tenant", "entity:<slug>" or "bu:<slug>"
    level      text NOT NULL CHECK (level IN ('hard', 'advisory')),
    module     text NOT NULL,
    enabled    boolean NOT NULL DEFAULT true,
    created_by text NOT NULL,
    updated_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
