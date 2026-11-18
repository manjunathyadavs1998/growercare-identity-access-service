-- SPEC-IAM-04 reference data for the UI. Statement ids: reference.<name>

-- R100: a country's territory tree, states first.
-- name: territories
SELECT t.territory_id, t.parent_territory_id, t.territory_code, t.name, t.territory_level
  FROM iam.territory t
 WHERE t.country_code = :country
 ORDER BY CASE t.territory_level WHEN 'STATE' THEN 1 WHEN 'DISTRICT' THEN 2 ELSE 3 END, t.name

-- name: countryExists
SELECT count(*) FROM iam.country c WHERE c.country_code = :country

-- R102: roles up to a level.
-- name: rolesUpTo
SELECT r.role_code, r.name, r.scope_kind, r.allowed_user_type
  FROM iam.role r
 WHERE r.role_level <= :level
 ORDER BY r.role_level, r.role_code

-- R104: ACTIVE staff with an active case:transition grant covering the territory (itself, an ancestor, its country or
-- region, or GLOBAL) and the BU (no BU rows = every BU). One row per user and role.
-- name: assignable
WITH RECURSIVE up (territory_id, parent_territory_id) AS (
    SELECT t.territory_id, t.parent_territory_id FROM iam.territory t WHERE t.territory_id = :territoryId
    UNION
    SELECT p.territory_id, p.parent_territory_id FROM up JOIN iam.territory p ON p.territory_id = up.parent_territory_id
)
SELECT DISTINCT u.user_id, u.display_name, g.role_code
  FROM iam.user_account u
  JOIN iam.role_grant g ON g.user_id = u.user_id
  JOIN iam.role r ON r.role_code = g.role_code
  JOIN iam.role_permission rp ON rp.role_code = g.role_code AND rp.permission_code = 'case:transition'
 WHERE u.user_type = 'STAFF'
   AND u.status = 'ACTIVE'
   AND g.revoked_at IS NULL
   AND g.valid_from <= now()
   AND (g.valid_to IS NULL OR g.valid_to > now())
   AND (r.scope_kind = 'GLOBAL'
        OR EXISTS (SELECT 1 FROM iam.grant_geo_scope s
                    WHERE s.grant_id = g.grant_id
                      AND (s.territory_id IN (SELECT territory_id FROM up)
                           OR s.country_code = :country
                           OR s.region_code = (SELECT c.region_code FROM iam.country c WHERE c.country_code = :country))))
   AND (NOT EXISTS (SELECT 1 FROM iam.grant_bu_scope b WHERE b.grant_id = g.grant_id)
        OR EXISTS (SELECT 1 FROM iam.grant_bu_scope b WHERE b.grant_id = g.grant_id AND b.bu_code = :buCode))
 ORDER BY u.display_name, u.user_id, g.role_code
