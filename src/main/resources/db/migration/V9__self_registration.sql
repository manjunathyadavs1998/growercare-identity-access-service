-- =====================================================================================================
-- identity-access-service · V9 · grower self-registration (SPEC-IAM-03 D4)
-- The calling code of each country: a self-registering grower's phone (the Keycloak username) must belong to the
-- country they choose. Expand only: the column is filled for every existing country before it becomes NOT NULL.
-- =====================================================================================================

ALTER TABLE iam.country ADD COLUMN calling_code varchar(4);
UPDATE iam.country SET calling_code = '91' WHERE country_code = 'IN';
UPDATE iam.country SET calling_code = '55' WHERE country_code = 'BR';
ALTER TABLE iam.country ALTER COLUMN calling_code SET NOT NULL;
ALTER TABLE iam.country ADD CONSTRAINT country_calling_code_check CHECK (calling_code ~ '^[1-9][0-9]{0,3}$');

-- D5: self-registered growers carry only the last 4 digits (the phone key lives in grower-service). The old rule
-- "HMAC and last 4 together" becomes "an HMAC needs its last 4": last 4 alone is allowed, an HMAC alone still is not.
ALTER TABLE iam.user_account DROP CONSTRAINT user_phone_parts_together;
ALTER TABLE iam.user_account ADD CONSTRAINT user_phone_hmac_needs_last4 CHECK (phone_hmac IS NULL OR phone_last4 IS NOT NULL);
