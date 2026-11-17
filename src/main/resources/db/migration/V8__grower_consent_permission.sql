-- =====================================================================================================
-- identity-access-service · V8 · grower:consent (SPEC-GRW-03 D7, growercare-grower-service)
-- Start and confirm a grower's phone verification (OTP) and record consent, for a grower in scope. Retailers need it
-- for assisted onboarding (PRD J2) although they cannot edit growers. Changing optional consents stays the grower's own
-- action (enforced by grower-service, not by this permission).
-- =====================================================================================================

INSERT INTO iam.permission (permission_code, description) VALUES
    ('grower:consent', 'Verify a grower''s phone (OTP) and record consent within scope');

INSERT INTO iam.role_permission (role_code, permission_code)
SELECT m.role_code, 'grower:consent'
  FROM (VALUES ('GROWER'), ('RETAILER_USER'), ('RETAILER_ADMIN'), ('FIELD_AGRONOMIST'), ('TERRITORY_MANAGER'), ('CARE_AGENT'))
       AS m (role_code);   -- the FK rejects a typo in a role code
