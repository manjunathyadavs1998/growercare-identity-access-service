-- SPEC-IAM-02 user directory. Statement ids: directory.<name>

-- R80/R83/R86: users in the admin's visible countries matching every filter, keyset by user id.
-- q matches an exact user id, or the start of a name word; a GROWER's name only where the admin may see it unmasked (D6).
-- name: search
SELECT u.user_id, u.user_type, u.home_country_code, u.partner_org_id, u.display_name, u.phone_last4, u.status
  FROM iam.user_account u
 WHERE (CAST(:allCountries AS boolean) OR u.home_country_code IN (:countries))
   AND (CAST(:country AS varchar) IS NULL OR u.home_country_code = CAST(:country AS varchar))
   AND (CAST(:userType AS varchar) IS NULL OR u.user_type = CAST(:userType AS varchar))
   AND (CAST(:status AS varchar) IS NULL OR u.status = CAST(:status AS varchar))
   AND (CAST(:prefix AS varchar) IS NULL
        OR u.user_id = CAST(:qUserId AS bigint)
        OR ((lower(u.display_name) LIKE CAST(:prefix AS varchar) ESCAPE '\'
             OR lower(u.display_name) LIKE CAST(:wordPrefix AS varchar) ESCAPE '\')
            AND (u.user_type <> 'GROWER' OR CAST(:allFullCountries AS boolean) OR u.home_country_code IN (:fullCountries))))
   AND u.user_id > :afterUserId
 ORDER BY u.user_id
 LIMIT :limit

-- R81: one user (visibility is checked by the caller).
-- name: user
SELECT u.user_id, u.user_type, u.home_country_code, u.partner_org_id, u.display_name, u.phone_last4, u.status
  FROM iam.user_account u
 WHERE u.user_id = :userId
