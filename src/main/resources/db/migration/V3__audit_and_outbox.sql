-- =====================================================================================================
-- identity-access-service · V3 · Audit trail and transactional outbox
-- =====================================================================================================

-- Append-only security audit (grant changes, denials, unmask events). No FKs on purpose: audit rows must
-- survive any later change to the rows they describe.
CREATE TABLE iam.audit_event (
    audit_id      bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at   timestamptz  NOT NULL DEFAULT now(),
    actor_user_id bigint,
    action        varchar(64)  NOT NULL CHECK (action ~ '^[a-z]+(\.[a-z-]+)+$'),   -- e.g. grant.create
    target_type   varchar(32)  NOT NULL,
    target_id     varchar(64)  NOT NULL,
    country_code  char(2),
    outcome       varchar(8)   NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED')),
    reason        varchar(300),
    trace_id      varchar(32)
);
CREATE INDEX audit_event_target_ix ON iam.audit_event (target_type, target_id, occurred_at DESC);
CREATE INDEX audit_event_actor_ix ON iam.audit_event (actor_user_id, occurred_at DESC);
-- Runtime role may append but never rewrite history.
REVOKE UPDATE, DELETE, TRUNCATE ON iam.audit_event FROM ${app_role};

-- Outbox: written in the same transaction as the state change; Debezium's outbox router publishes it
-- (ADR-012). The payload is the serialized event, so jsonb is appropriate here (it is a message, not data).
CREATE TABLE iam.outbox (
    event_id       uuid         PRIMARY KEY,
    aggregate_type varchar(64)  NOT NULL,
    aggregate_id   varchar(64)  NOT NULL,
    event_type     varchar(128) NOT NULL,
    payload        jsonb        NOT NULL,
    occurred_at    timestamptz  NOT NULL DEFAULT now(),
    trace_id       varchar(32)
);
CREATE INDEX outbox_occurred_ix ON iam.outbox (occurred_at);
