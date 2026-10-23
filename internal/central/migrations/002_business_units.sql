-- Hierarchy: tenant > entity (company) > business unit (product).
CREATE TABLE business_units (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  uuid NOT NULL REFERENCES tenants(id),
    entity_id  uuid NOT NULL REFERENCES entities(id),
    slug       text NOT NULL,
    name       text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

-- A membership is tenant-wide, on an entity (inherited by its BUs) or on one BU.
ALTER TABLE memberships ADD COLUMN bu_id uuid REFERENCES business_units(id);
ALTER TABLE memberships DROP CONSTRAINT memberships_check;
ALTER TABLE memberships DROP CONSTRAINT memberships_user_id_tenant_id_entity_id_role_key;
ALTER TABLE memberships ADD CONSTRAINT memberships_scope_role CHECK (
       (entity_id IS NULL AND bu_id IS NULL AND role IN ('tenant_admin', 'finops', 'security', 'auditor'))
    OR (num_nonnulls(entity_id, bu_id) = 1 AND role IN ('admin', 'manager', 'developer', 'viewer')));
ALTER TABLE memberships ADD CONSTRAINT memberships_unique UNIQUE NULLS NOT DISTINCT (user_id, tenant_id, entity_id, bu_id, role);
