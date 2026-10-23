-- Large objects can live in the tenant's own bucket: the database keeps the key.
ALTER TABLE state_versions ALTER COLUMN data DROP NOT NULL;
ALTER TABLE state_versions ADD COLUMN object_key text;
ALTER TABLE runs ADD COLUMN plan_object text;
