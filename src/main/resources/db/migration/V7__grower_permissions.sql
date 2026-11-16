-- =====================================================================================================
-- identity-access-service · V7 · grower permissions (SPEC-GRW-01 D7, growercare-grower-service)
-- grower:create — register (self or assisted) · grower:read — read and find growers in scope ·
-- grower:update — change profile fields. Scope comes from the grant (OWN / ORG / geo), as for cases.
-- Retailers onboard and read growers but do not edit them; admins and management get none (no grower data).
-- =====================================================================================================

INSERT INTO iam.permission (permission_code, description) VALUES
    ('grower:create', 'Register growers (self, or assisted onboarding) within scope'),
    ('grower:read',   'Read and find growers within scope'),
    ('grower:update', 'Update grower profiles within scope');

INSERT INTO iam.role_permission (role_code, permission_code)
SELECT m.role_code, perm.code
  FROM (VALUES
    ('GROWER',            'grower:create,grower:read,grower:update'),
    ('RETAILER_USER',     'grower:create,grower:read'),
    ('RETAILER_ADMIN',    'grower:create,grower:read'),
    ('FIELD_AGRONOMIST',  'grower:create,grower:read,grower:update'),
    ('TERRITORY_MANAGER', 'grower:create,grower:read,grower:update'),
    ('CARE_AGENT',        'grower:create,grower:read,grower:update')
  ) AS m (role_code, perms)
  CROSS JOIN LATERAL unnest(string_to_array(m.perms, ',')) AS perm (code);   -- FKs reject a typo (role or permission)
