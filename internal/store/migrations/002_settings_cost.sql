-- Tenant-level settings (risk policy, and later Git and drift options) and
-- the plan's approximate cost estimate.
CREATE TABLE tenant_settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE runs ADD COLUMN cost jsonb;
