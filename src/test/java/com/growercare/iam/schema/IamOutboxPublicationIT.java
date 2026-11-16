package com.growercare.iam.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

import com.growercare.testsupport.PostgresTestDatabase;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;

/** SPEC-PLAT-04 R52, R53, R62 for gc_iam: Debezium streams iam.outbox (+ heartbeat) only. */
class IamOutboxPublicationIT {

    private static PostgresTestDatabase db;

    @BeforeAll
    static void migrate() {
        db = PostgresTestDatabase.forService("gc_iam");
        Flyway.configure()
                .dataSource(db.ownerDataSource())
                .schemas("iam").defaultSchema("iam").createSchemas(true)
                .locations("classpath:db/migration", "classpath:db/dev-seed")
                .placeholders(Map.of("app_role", db.appUser(), "cdc_role", PostgresTestDatabase.CDC_ROLE))
                .cleanDisabled(true)
                .load().migrate();
    }

    @Test
    void platE61PublicationContainsOnlyTheOutboxAndTheHeartbeat() {
        var owner = JdbcClient.create(db.ownerDataSource());
        assertThat(owner.sql("SELECT schemaname || '.' || tablename FROM pg_publication_tables WHERE pubname = 'gc_outbox'")
                .query(String.class).set()).isEqualTo(Set.of("iam.outbox", "iam.cdc_heartbeat"));
        assertThat(owner.sql("SELECT pubdelete OR pubtruncate FROM pg_publication WHERE pubname = 'gc_outbox'")
                .query(Boolean.class).single()).isFalse();
    }

    /** statement run as gc_cdc, the table Postgres refuses (null = allowed). */
    static Stream<Arguments> cdcPrivileges() {
        return Stream.of(
                argumentSet("PLAT-E62e iam.outbox is readable", "SELECT count(*) FROM iam.outbox", null),
                argumentSet("PLAT-E62f user accounts are not", "SELECT count(*) FROM iam.user_account", "user_account"),
                argumentSet("PLAT-E62g grants are not", "SELECT count(*) FROM iam.role_grant", "role_grant"),
                argumentSet("PLAT-E76d heartbeat upsert is allowed", """
                        INSERT INTO iam.cdc_heartbeat (id, beat_at) VALUES (1, now())
                        ON CONFLICT (id) DO UPDATE SET beat_at = EXCLUDED.beat_at""", null));
    }

    @ParameterizedTest
    @MethodSource("cdcPrivileges")
    void cdcRoleSeesOutboxOnly(String sql, String deniedTable) {
        var cdc = new org.springframework.jdbc.core.JdbcTemplate(db.cdcDataSource());   // runs SELECT and DML alike
        if (deniedTable == null) {
            cdc.execute(sql);
        } else {
            assertThatThrownBy(() -> cdc.execute(sql))
                    .isInstanceOf(DataAccessException.class)
                    .hasRootCauseMessage("ERROR: permission denied for table " + deniedTable);
        }
    }
}
