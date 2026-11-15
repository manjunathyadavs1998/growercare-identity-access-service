-- =====================================================================================================
-- DEV/TEST ONLY (location classpath:db/dev-seed, enabled by gc.dev-seed=true). Never enabled in prod.
-- Mirrors local-dev/keycloak/growercare-realm.json: external_subject = the Keycloak user id.
-- =====================================================================================================

INSERT INTO iam.partner_org (partner_org_id, country_code, org_type, parent_partner_org_id, legal_name, tax_id, status) VALUES
    (503, 'IN', 'DISTRIBUTOR', NULL, 'Deccan Agri Distributors Pvt Ltd', '27AAACD1234F1Z5', 'ACTIVE'),
    (501, 'IN', 'RETAILER',    503,  'Patil Agro Store',                 '27AAAPP5678K1Z2', 'ACTIVE'),
    (502, 'IN', 'RETAILER',    NULL, 'Krishi Kendra Nashik',             '27AABCK9012M1Z8', 'ACTIVE');

INSERT INTO iam.user_account (user_id, external_subject, user_type, home_country_code, partner_org_id, display_name, email) VALUES
    (1,   '6f1c0a10-0001-4a00-8000-000000000001', 'GROWER',  'IN', NULL, 'Ramesh Patil',     NULL),
    (2,   '6f1c0a10-0002-4a00-8000-000000000002', 'GROWER',  'IN', NULL, 'Sunita Rao',       NULL),
    (3,   '6f1c0a10-0003-4a00-8000-000000000003', 'GROWER',  'BR', NULL, 'Joao Silva',       NULL),
    (101, '6f1c0a10-0101-4a00-8000-000000000101', 'STAFF',   'IN', NULL, 'Anita Care',       'care.in@growercare.test'),
    (102, '6f1c0a10-0102-4a00-8000-000000000102', 'STAFF',   'IN', NULL, 'Vikram Agro',      'agro.in@growercare.test'),
    (103, '6f1c0a10-0103-4a00-8000-000000000103', 'STAFF',   'IN', NULL, 'Kiran Territory',  'tm.in@growercare.test'),
    (104, '6f1c0a10-0104-4a00-8000-000000000104', 'STAFF',   'IN', NULL, 'Meera Admin',      'admin.in@growercare.test'),
    (105, '6f1c0a10-0105-4a00-8000-000000000105', 'STAFF',   'BR', NULL, 'Ana Cuidado',      'care.br@growercare.test'),
    (201, '6f1c0a10-0201-4a00-8000-000000000201', 'PARTNER', 'IN', 501,  'Suresh (Patil Agro Store)',   'retailer.in@growercare.test'),
    (202, '6f1c0a10-0202-4a00-8000-000000000202', 'PARTNER', 'IN', 502,  'Farid (Krishi Kendra)',       'retailer2.in@growercare.test');

-- Bootstrap grants have granted_by_user_id NULL (system); every later grant must name a granting admin.
INSERT INTO iam.role_grant (grant_id, user_id, role_code, grant_reason) VALUES
    (1,  1,   'GROWER',            'dev seed: self-registered grower'),
    (2,  2,   'GROWER',            'dev seed: self-registered grower'),
    (3,  3,   'GROWER',            'dev seed: self-registered grower'),
    (4,  101, 'CARE_AGENT',        'dev seed'),
    (5,  102, 'FIELD_AGRONOMIST',  'dev seed'),
    (6,  103, 'TERRITORY_MANAGER', 'dev seed'),
    (7,  104, 'COUNTRY_ADMIN',     'dev seed'),
    (8,  105, 'CARE_AGENT',        'dev seed'),
    (9,  201, 'RETAILER_USER',     'dev seed'),
    (10, 202, 'RETAILER_USER',     'dev seed');

INSERT INTO iam.grant_geo_scope (grant_id, region_code, country_code, territory_id) VALUES
    (1,  NULL, 'IN', NULL),
    (2,  NULL, 'IN', NULL),
    (3,  NULL, 'BR', NULL),
    (4,  NULL, 'IN', NULL),
    (5,  NULL, NULL, 1002),     -- agronomist: Pune district
    (6,  NULL, NULL, 1001),     -- territory manager: Maharashtra (includes its districts)
    (7,  NULL, 'IN', NULL),
    (8,  NULL, 'BR', NULL),
    (9,  NULL, 'IN', NULL),
    (10, NULL, 'IN', NULL);

INSERT INTO iam.grant_bu_scope (grant_id, bu_code) VALUES
    (5, 'CP');                  -- agronomist: crop protection only

-- Keep identity sequences ahead of the explicit dev IDs.
SELECT setval(pg_get_serial_sequence('iam.partner_org', 'partner_org_id'), 10000);
SELECT setval(pg_get_serial_sequence('iam.user_account', 'user_id'), 10000);
SELECT setval(pg_get_serial_sequence('iam.role_grant', 'grant_id'), 10000);
