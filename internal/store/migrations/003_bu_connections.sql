-- Hierarchy: tenant > entity (company) > business unit (product).
-- Resources are scoped to a business unit and also record its entity.
ALTER TABLE environments RENAME COLUMN entity TO bu;
ALTER TABLE environments ADD COLUMN entity text NOT NULL DEFAULT '';
ALTER TABLE stacks RENAME COLUMN entity TO bu;
ALTER TABLE stacks ADD COLUMN entity text NOT NULL DEFAULT '';
ALTER INDEX stacks_entity_idx RENAME TO stacks_bu_idx;
ALTER TABLE audit_events RENAME COLUMN entity TO bu;

-- Cloud provider connections, registered once per tenant (identifiers only)
-- and usable by the listed entities (empty = every entity).
CREATE TABLE cloud_connections (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text NOT NULL UNIQUE,
    cloud      jsonb NOT NULL,
    entities   text[] NOT NULL DEFAULT '{}',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Environments now reference a connection instead of embedding a cloud;
-- NULL means no cloud (modules that need no credentials).
ALTER TABLE environments ADD COLUMN connection_id uuid REFERENCES cloud_connections(id);
ALTER TABLE environments DROP COLUMN cloud;
