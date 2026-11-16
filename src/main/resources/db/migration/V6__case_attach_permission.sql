-- =====================================================================================================
-- identity-access-service · V6 · permission case:attach (SPEC-CASE-05 D8)
-- Granted to every role that may post grower- or partner-visible comments.
-- =====================================================================================================

INSERT INTO iam.permission (permission_code, description) VALUES ('case:attach', 'Upload evidence and comment attachments');

INSERT INTO iam.role_permission (role_code, permission_code)
SELECT DISTINCT rp.role_code, 'case:attach'
  FROM iam.role_permission rp
 WHERE rp.permission_code IN ('comment:post-public', 'comment:post-partner');
