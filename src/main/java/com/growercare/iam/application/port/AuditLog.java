package com.growercare.iam.application.port;

/** Append-only security audit (iam.audit_event). */
public interface AuditLog {

    /** Records a successful action in the caller's transaction. */
    void success(Long actorUserId, String action, String targetType, String targetId, String countryCode, String reason);

    /** Records a denied action in its <b>own</b> transaction, so it survives the caller's rollback. */
    void denied(Long actorUserId, String action, String targetType, String targetId, String countryCode, String reason);
}
