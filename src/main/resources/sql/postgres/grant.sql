-- Grant administration (ACC-1, 2, 6). Statement ids: grant.<name>

-- name: findUser
SELECT u.user_id, u.external_subject, u.user_type, u.home_country_code, u.partner_org_id, u.status
  FROM iam.user_account u
 WHERE u.user_id = :userId

-- name: findRole
SELECT r.role_code, r.role_level, r.scope_kind, r.allowed_user_type, r.privileged
  FROM iam.role r
 WHERE r.role_code = :roleCode

-- name: activeRoleCodesOfUser
SELECT DISTINCT g.role_code
  FROM iam.role_grant g
 WHERE g.user_id = :userId
   AND g.revoked_at IS NULL
   AND (g.valid_to IS NULL OR g.valid_to > now())

-- Roles that conflict with :roleCode (pairs are stored once, in either column).
-- name: sodConflictsOf
SELECT CASE WHEN s.role_code_a = :roleCode THEN s.role_code_b ELSE s.role_code_a END AS conflicting_role
  FROM iam.sod_conflict s
 WHERE :roleCode IN (s.role_code_a, s.role_code_b)

-- name: territoryCountries
SELECT t.territory_id, t.country_code
  FROM iam.territory t
 WHERE t.territory_id IN (:territoryIds)

-- name: regionCountries
SELECT c.region_code, c.country_code
  FROM iam.country c
 WHERE c.region_code IN (:regionCodes) AND c.active

-- name: existingCountries
SELECT c.country_code FROM iam.country c WHERE c.country_code IN (:countryCodes)

-- name: existingRegions
SELECT r.region_code FROM iam.region r WHERE r.region_code IN (:regionCodes)

-- name: existingBusinessUnits
SELECT b.bu_code FROM iam.business_unit b WHERE b.bu_code IN (:buCodes)

-- name: insertGrant
INSERT INTO iam.role_grant (user_id, role_code, valid_to, granted_by_user_id, grant_reason)
VALUES (:userId, :roleCode, :validTo, :grantedBy, :reason)
RETURNING grant_id, valid_from

-- name: insertGeoScope
INSERT INTO iam.grant_geo_scope (grant_id, region_code, country_code, territory_id)
VALUES (:grantId, :regionCode, :countryCode, :territoryId)

-- name: insertBuScope
INSERT INTO iam.grant_bu_scope (grant_id, bu_code) VALUES (:grantId, :buCode)

-- name: findGrant
SELECT g.grant_id, g.user_id, g.role_code, g.valid_from, g.valid_to, g.granted_by_user_id, g.revoked_at
  FROM iam.role_grant g
 WHERE g.grant_id = :grantId

-- name: grantsOfUser
SELECT g.grant_id, g.user_id, g.role_code, g.valid_from, g.valid_to, g.granted_by_user_id, g.revoked_at
  FROM iam.role_grant g
 WHERE g.user_id = :userId
 ORDER BY g.grant_id

-- Raw (unexpanded) geo scope rows of grants, for display and for delegation checks.
-- name: geoScopesOfGrants
SELECT s.grant_id, s.region_code, s.country_code, s.territory_id
  FROM iam.grant_geo_scope s
 WHERE s.grant_id IN (:grantIds)

-- name: buScopesOfGrants
SELECT b.grant_id, b.bu_code FROM iam.grant_bu_scope b WHERE b.grant_id IN (:grantIds)

-- Revocation is a recorded event, never a DELETE. Only an active grant can be revoked (0 rows → already revoked).
-- name: revokeGrant
UPDATE iam.role_grant
   SET revoked_at = now(), revoked_by_user_id = :revokedBy, revoke_reason = :reason, version = version + 1
 WHERE grant_id = :grantId AND revoked_at IS NULL
RETURNING version
