package com.growercare.iam.adapters.out.persistence;

import com.growercare.common.sql.NamedSqlRegistry;
import com.growercare.common.web.TraceIds;
import com.growercare.iam.application.port.AuditLog;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Writes iam.audit_event (append-only for the runtime role). Reasons are codes or admin text, never PII. */
@Component
class JdbcAuditLog implements AuditLog {

    private final JdbcClient jdbc;
    private final NamedSqlRegistry sql;

    JdbcAuditLog(JdbcClient jdbc, NamedSqlRegistry sql) {
        this.jdbc = jdbc;
        this.sql = sql;
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public void success(Long actorUserId, String action, String targetType, String targetId, String countryCode, String reason) {
        insert(actorUserId, action, targetType, targetId, countryCode, "SUCCESS", reason);
    }

    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void denied(Long actorUserId, String action, String targetType, String targetId, String countryCode, String reason) {
        insert(actorUserId, action, targetType, targetId, countryCode, "DENIED", reason);
    }

    private void insert(Long actor, String action, String targetType, String targetId, String country, String outcome, String reason) {
        jdbc.sql(sql.get("audit.insert"))
                .param("actorUserId", actor)
                .param("action", action)
                .param("targetType", targetType)
                .param("targetId", targetId)
                .param("countryCode", country)
                .param("outcome", outcome)
                .param("reason", reason == null ? null : reason.substring(0, Math.min(300, reason.length())))
                .param("traceId", TraceIds.currentOrNull())
                .update();
    }
}
