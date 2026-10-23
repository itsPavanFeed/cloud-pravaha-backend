-- Stacks defined in the tenant's contracts repository are managed by Git:
-- the UI and API cannot edit them, and source_ref records the commit.
ALTER TABLE stacks ADD COLUMN managed_by text NOT NULL DEFAULT 'ui' CHECK (managed_by IN ('ui', 'git'));
ALTER TABLE stacks ADD COLUMN source_ref text NOT NULL DEFAULT '';
