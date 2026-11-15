-- Effective-grant resolution (Keycloak subject → user → active grants → permissions + expanded scope).
-- Statement ids: principal.<name>

-- name: userBySubject
SELECT u.user_id, u.external_subject, u.user_type, u.home_country_code, u.partner_org_id, u.status
  FROM iam.user_account u
 WHERE u.external_subject = :subject

-- name: activeGrantsByUser
SELECT g.grant_id, g.role_code, r.role_level, r.scope_kind, r.pii_clearance, g.valid_to
  FROM iam.role_grant g
  JOIN iam.role r ON r.role_code = g.role_code
 WHERE g.user_id = :userId
   AND g.revoked_at IS NULL
   AND g.valid_from <= now()
   AND (g.valid_to IS NULL OR g.valid_to > now())
 ORDER BY g.grant_id

-- name: permissionsByGrants
SELECT g.grant_id, rp.permission_code
  FROM iam.role_grant g
  JOIN iam.role_permission rp ON rp.role_code = g.role_code
 WHERE g.grant_id IN (:grantIds)

-- Countries covered completely: direct country scopes + every active country of a region scope.
-- name: countriesByGrants
SELECT s.grant_id, s.country_code
  FROM iam.grant_geo_scope s
 WHERE s.grant_id IN (:grantIds) AND s.country_code IS NOT NULL
UNION
SELECT s.grant_id, c.country_code
  FROM iam.grant_geo_scope s
  JOIN iam.country c ON c.region_code = s.region_code
 WHERE s.grant_id IN (:grantIds) AND s.region_code IS NOT NULL

-- Territory scopes expanded to all descendants (a state grant covers its districts and sales areas).
-- name: territoriesByGrants
WITH RECURSIVE scoped (grant_id, territory_id) AS (
    SELECT s.grant_id, s.territory_id
      FROM iam.grant_geo_scope s
     WHERE s.grant_id IN (:grantIds) AND s.territory_id IS NOT NULL
    UNION
    SELECT p.grant_id, child.territory_id
      FROM scoped p
      JOIN iam.territory child ON child.parent_territory_id = p.territory_id
)
SELECT grant_id, territory_id FROM scoped

-- name: businessUnitsByGrants
SELECT b.grant_id, b.bu_code
  FROM iam.grant_bu_scope b
 WHERE b.grant_id IN (:grantIds)
