-- devops: approves activating module and policy releases (tenant-wide).
ALTER TABLE memberships DROP CONSTRAINT memberships_scope_role;
ALTER TABLE memberships ADD CONSTRAINT memberships_scope_role CHECK (
       (entity_id IS NULL AND bu_id IS NULL AND role IN ('tenant_admin', 'finops', 'security', 'devops', 'auditor'))
    OR (num_nonnulls(entity_id, bu_id) = 1 AND role IN ('admin', 'manager', 'developer', 'viewer')));
