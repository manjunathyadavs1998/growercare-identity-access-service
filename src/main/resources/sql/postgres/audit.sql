-- Append-only security audit. Statement ids: audit.<name>

-- name: insert
INSERT INTO iam.audit_event (actor_user_id, action, target_type, target_id, country_code, outcome, reason, trace_id)
VALUES (:actorUserId, :action, :targetType, :targetId, :countryCode, :outcome, :reason, :traceId)
