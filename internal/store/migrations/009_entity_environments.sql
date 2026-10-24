-- Environments belong to an entity (product): every business unit of the entity
-- can deploy to them, so a name is unique within its entity, not the tenant.
ALTER TABLE environments DROP CONSTRAINT IF EXISTS environments_name_key;
ALTER TABLE environments ADD CONSTRAINT environments_entity_name_key UNIQUE (entity, name);
ALTER TABLE environments DROP COLUMN bu;
CREATE INDEX environments_entity_idx ON environments (entity);
