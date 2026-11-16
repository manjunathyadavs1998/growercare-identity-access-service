-- =====================================================================================================
-- identity-access-service · V5 · Debezium outbox publication + CDC heartbeat (SPEC-PLAT-04 D8, R52, R53, R62)
-- The CDC role ${cdc_role} is cluster-wide (local-dev/postgres/02-cdc-role.sh); it sees the outbox only.
-- =====================================================================================================

-- R62: Debezium upserts this single row every 10 s so the replication slot advances even without events.
CREATE TABLE iam.cdc_heartbeat (
    id      smallint    PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    beat_at timestamptz NOT NULL
);

-- R52: exactly the outbox + heartbeat; insert/update only, so housekeeping deletes are never streamed.
CREATE PUBLICATION gc_outbox FOR TABLE iam.outbox, iam.cdc_heartbeat WITH (publish = 'insert, update');

-- R53: least privilege for the connector.
GRANT USAGE ON SCHEMA iam TO ${cdc_role};
GRANT SELECT ON iam.outbox TO ${cdc_role};
GRANT SELECT, INSERT, UPDATE ON iam.cdc_heartbeat TO ${cdc_role};
REVOKE ALL ON iam.cdc_heartbeat FROM ${app_role};
