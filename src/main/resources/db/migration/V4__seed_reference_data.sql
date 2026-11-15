-- =====================================================================================================
-- identity-access-service · V4 · Reference data: geography, BUs, permissions, roles (BRD §2, §3)
-- Country index / case_no slot allocation (doc 04, ID-5) — CC ranges by region:
--   NA 10–29 · LATAM 30–49 · EAME 50–69 · APAC 70–89 · 90–98 spare · 99 sandbox
-- Only the pilot countries are active; indices are never reused.
-- =====================================================================================================

INSERT INTO iam.region (region_code, name) VALUES
    ('NA', 'North America'), ('LATAM', 'Latin America'), ('EAME', 'Europe, Africa, Middle East'), ('APAC', 'Asia Pacific');

INSERT INTO iam.country (country_code, region_code, name, country_ix, case_no_cc, time_zone, currency_code, default_locale, active) VALUES
    ('IN', 'APAC',  'India',  46, 71, 'Asia/Kolkata',      'INR', 'en-IN', true),
    ('BR', 'LATAM', 'Brazil',  8, 31, 'America/Sao_Paulo', 'BRL', 'pt-BR', true);

INSERT INTO iam.territory (territory_id, country_code, parent_territory_id, territory_code, name, territory_level) VALUES
    (1001, 'IN', NULL, 'MH',        'Maharashtra',      'STATE'),
    (1002, 'IN', 1001, 'MH-PUNE',   'Pune',             'DISTRICT'),
    (1003, 'IN', 1001, 'MH-NASHIK', 'Nashik',           'DISTRICT'),
    (1004, 'IN', NULL, 'KA',        'Karnataka',        'STATE'),
    (1005, 'IN', 1004, 'KA-BLR-R',  'Bengaluru Rural',  'DISTRICT'),
    (2001, 'BR', NULL, 'SP',        'São Paulo',        'STATE'),
    (2002, 'BR', 2001, 'SP-RP',     'Ribeirão Preto',   'DISTRICT'),
    (2003, 'BR', NULL, 'MT',        'Mato Grosso',      'STATE');

INSERT INTO iam.business_unit (bu_code, name) VALUES
    ('CP', 'Crop Protection'), ('SEEDS', 'Seeds'), ('BIO', 'Biologicals'), ('PROF', 'Professional Solutions');

INSERT INTO iam.permission (permission_code, description) VALUES
    ('case:create',           'Raise a case (own, on behalf of a grower, or as staff)'),
    ('case:read',             'Read cases within scope'),
    ('case:assign',           'Assign or re-assign a case'),
    ('case:transition',       'Move a case through its workflow'),
    ('case:share',            'Share a case with a channel partner (grower consent)'),
    ('comment:read',          'Read case comments visible to the role'),
    ('comment:post-public',   'Post grower-visible comments'),
    ('comment:post-internal', 'Post internal staff notes'),
    ('comment:post-partner',  'Post partner-visible comments'),
    ('pii:unmask',            'Reveal masked personal data, with a reason (ACC-3)'),
    ('compensation:propose',  'Propose compensation (maker)'),
    ('compensation:approve',  'Approve compensation (checker)'),
    ('dashboard:read',        'Read dashboards for the grant scope'),
    ('user:read',             'Read user accounts within scope'),
    ('user:manage',           'Create, suspend or update user accounts within scope'),
    ('partner:manage',        'Onboard and manage partner organisations'),
    ('grant:read',            'Read role grants within scope'),
    ('grant:create',          'Grant roles within scope (delegation rules apply)'),
    ('grant:revoke',          'Revoke role grants within scope'),
    ('audit:read',            'Read audit and access-monitoring data'),
    ('config:manage',         'Manage global configuration and compliance-pack versions');

INSERT INTO iam.role (role_code, name, role_group, role_level, scope_kind, allowed_user_type, pii_clearance, privileged) VALUES
    ('GROWER',                'Grower',                     'GROWER',          10, 'OWN',       'GROWER',  'FULL',   false),
    ('RETAILER_USER',         'Retailer user',              'CHANNEL_PARTNER', 20, 'ORG',       'PARTNER', 'MASKED', false),
    ('RETAILER_ADMIN',        'Retailer admin',             'CHANNEL_PARTNER', 25, 'ORG',       'PARTNER', 'MASKED', false),
    ('DISTRIBUTOR_USER',      'Distributor user',           'CHANNEL_PARTNER', 20, 'ORG',       'PARTNER', 'MASKED', false),
    ('DISTRIBUTOR_ADMIN',     'Distributor admin',          'CHANNEL_PARTNER', 25, 'ORG',       'PARTNER', 'MASKED', false),
    ('FIELD_AGRONOMIST',      'Field agronomist',           'FIELD_STAFF',     30, 'ASSIGNED',  'STAFF',   'FULL',   false),
    ('TERRITORY_MANAGER',     'Territory manager',          'FIELD_STAFF',     40, 'TERRITORY', 'STAFF',   'FULL',   false),
    ('CARE_AGENT',            'Care agent',                 'CENTRAL',         30, 'COUNTRY',   'STAFF',   'MASKED', false),
    ('QUALITY_INVESTIGATOR',  'Quality investigator',       'CENTRAL',         40, 'COUNTRY',   'STAFF',   'FULL',   false),
    ('STEWARDSHIP_OFFICER',   'Stewardship officer',        'CENTRAL',         40, 'COUNTRY',   'STAFF',   'FULL',   false),
    ('FINANCE_ANALYST',       'Finance analyst (maker)',    'CENTRAL',         40, 'COUNTRY',   'STAFF',   'MASKED', false),
    ('FINANCE_APPROVER',      'Finance approver (checker)', 'CENTRAL',         45, 'COUNTRY',   'STAFF',   'MASKED', true),
    ('COUNTRY_MANAGER',       'Country manager',            'MANAGEMENT',      60, 'COUNTRY',   'STAFF',   'MASKED', false),
    ('REGIONAL_HEAD',         'Regional head',              'MANAGEMENT',      70, 'REGION',    'STAFF',   'MASKED', false),
    ('GLOBAL_EXECUTIVE',      'Global executive',           'MANAGEMENT',      80, 'GLOBAL',    'STAFF',   'NONE',   false),
    ('AUDITOR',               'Auditor (time-boxed)',       'GOVERNANCE',      50, 'COUNTRY',   'STAFF',   'MASKED', true),
    ('COUNTRY_ADMIN',         'Country admin',              'GOVERNANCE',      60, 'COUNTRY',   'STAFF',   'MASKED', true),
    ('DPO',                   'Data protection officer',    'GOVERNANCE',      65, 'REGION',    'STAFF',   'FULL',   true),
    ('REGIONAL_ADMIN',        'Regional admin',             'GOVERNANCE',      70, 'REGION',    'STAFF',   'MASKED', true),
    ('GLOBAL_PLATFORM_ADMIN', 'Global platform admin',      'GOVERNANCE',      90, 'GLOBAL',    'STAFF',   'NONE',   true);

INSERT INTO iam.role_permission (role_code, permission_code)
SELECT r.role_code, p.permission_code
  FROM (VALUES
    ('GROWER',               'case:create,case:read,case:share,comment:read,comment:post-public'),
    ('RETAILER_USER',        'case:create,case:read,comment:read,comment:post-partner'),
    ('RETAILER_ADMIN',       'case:create,case:read,comment:read,comment:post-partner,user:read'),
    ('DISTRIBUTOR_USER',     'case:read,comment:read,comment:post-partner'),
    ('DISTRIBUTOR_ADMIN',    'case:read,comment:read,comment:post-partner,user:read'),
    ('FIELD_AGRONOMIST',     'case:create,case:read,case:transition,comment:read,comment:post-public,comment:post-internal'),
    ('TERRITORY_MANAGER',    'case:create,case:read,case:assign,case:transition,comment:read,comment:post-public,comment:post-internal,dashboard:read'),
    ('CARE_AGENT',           'case:create,case:read,case:assign,case:transition,comment:read,comment:post-public,comment:post-internal,pii:unmask'),
    ('QUALITY_INVESTIGATOR', 'case:read,case:transition,comment:read,comment:post-public,comment:post-internal,compensation:propose'),
    ('STEWARDSHIP_OFFICER',  'case:read,case:transition,comment:read,comment:post-internal'),
    ('FINANCE_ANALYST',      'case:read,comment:read,compensation:propose'),
    ('FINANCE_APPROVER',     'case:read,comment:read,compensation:approve'),
    ('COUNTRY_MANAGER',      'case:read,comment:read,dashboard:read'),
    ('REGIONAL_HEAD',        'dashboard:read'),
    ('GLOBAL_EXECUTIVE',     'dashboard:read'),
    ('AUDITOR',              'case:read,comment:read,audit:read,grant:read'),
    ('COUNTRY_ADMIN',        'user:read,user:manage,partner:manage,grant:read,grant:create,grant:revoke,audit:read'),
    ('DPO',                  'user:read,audit:read,pii:unmask'),
    ('REGIONAL_ADMIN',       'user:read,user:manage,partner:manage,grant:read,grant:create,grant:revoke,audit:read'),
    ('GLOBAL_PLATFORM_ADMIN','config:manage,grant:read,grant:create,grant:revoke,audit:read')
  ) AS m (role_code, perms)
  JOIN iam.role r ON r.role_code = m.role_code
  CROSS JOIN LATERAL unnest(string_to_array(m.perms, ',')) AS perm (code)
  JOIN iam.permission p ON p.permission_code = perm.code;   -- a typo here would silently drop a row, so V4 is checked by a test

INSERT INTO iam.sod_conflict (role_code_a, role_code_b, reason) VALUES
    ('FINANCE_ANALYST', 'FINANCE_APPROVER', 'Maker and checker of compensation must be different people (ACC-6)'),
    ('AUDITOR',         'COUNTRY_ADMIN',    'An auditor cannot administer the access they audit'),
    ('AUDITOR',         'REGIONAL_ADMIN',   'An auditor cannot administer the access they audit');
