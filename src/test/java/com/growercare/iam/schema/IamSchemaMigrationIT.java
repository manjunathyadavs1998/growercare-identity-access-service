package com.growercare.iam.schema;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.growercare.testsupport.PostgresTestDatabase;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;

/** IAM schema: migrations, reference data completeness, integrity rules and least privilege. */
class IamSchemaMigrationIT {

    private static JdbcClient app;

    @BeforeAll
    static void migrate() {
        var db = PostgresTestDatabase.forService("gc_iam");
        var result = Flyway.configure()
                .dataSource(db.ownerDataSource())
                .schemas("iam").defaultSchema("iam").createSchemas(true)
                .locations("classpath:db/migration", "classpath:db/dev-seed")
                .placeholders(Map.of("app_role", db.appUser(), "cdc_role", PostgresTestDatabase.CDC_ROLE))
                .cleanDisabled(true)
                .load().migrate();
        assertThat(result.success).isTrue();
        app = JdbcClient.create(db.appDataSource());
    }

    @Test
    void everyRoleHasPermissionsAndNoMappingWasSilentlyDropped() {
        int mappings = app.sql("SELECT count(*) FROM iam.role_permission").query(Integer.class).single();
        assertThat(mappings).isEqualTo(90);   // sum of the V4 permission lists; a typo in V4 would lower it
        var rolesWithout = app.sql("""
                SELECT r.role_code FROM iam.role r
                 WHERE NOT EXISTS (SELECT 1 FROM iam.role_permission rp WHERE rp.role_code = r.role_code)""")
                .query(String.class).list();
        assertThat(rolesWithout).isEmpty();
    }

    @Test
    void sodConflictsCoverMakerChecker() {
        var conflict = app.sql("""
                SELECT count(*) FROM iam.sod_conflict
                 WHERE role_code_a = 'FINANCE_ANALYST' AND role_code_b = 'FINANCE_APPROVER'""")
                .query(Integer.class).single();
        assertThat(conflict).isEqualTo(1);
    }

    @Test
    void devSeedGrantsResolveToScopes() {
        record Scope(String role, String country, Long territory) { }
        var agronomist = app.sql("""
                SELECT g.role_code, s.country_code, s.territory_id
                  FROM iam.role_grant g
                  JOIN iam.user_account u ON u.user_id = g.user_id
                  JOIN iam.grant_geo_scope s ON s.grant_id = g.grant_id
                 WHERE u.external_subject = '6f1c0a10-0102-4a00-8000-000000000102'::uuid AND g.revoked_at IS NULL""")
                .query((rs, n) -> new Scope(rs.getString(1), rs.getString(2), rs.getObject(3, Long.class)))
                .single();
        assertThat(agronomist).isEqualTo(new Scope("FIELD_AGRONOMIST", null, 1002L));
    }

    @Test
    void selfGrantIsRejectedByTheDatabase() {
        assertThatThrownBy(() -> app.sql("""
                INSERT INTO iam.role_grant (user_id, role_code, granted_by_user_id, grant_reason)
                VALUES (104, 'COUNTRY_ADMIN', 104, 'self promotion')""").update())
                .isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("grant_no_self_grant");
    }

    @Test
    void geoScopeNeedsExactlyOneLevel() {
        assertThatThrownBy(() -> app.sql("""
                INSERT INTO iam.grant_geo_scope (grant_id, region_code, country_code) VALUES (4, 'APAC', 'IN')""").update())
                .isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("geo_scope_exactly_one");
    }

    @Test
    void territoryParentMustBeInTheSameCountry() {
        assertThatThrownBy(() -> app.sql("""
                INSERT INTO iam.territory (territory_id, country_code, parent_territory_id, territory_code, name, territory_level)
                VALUES (9999, 'BR', 1001, 'BAD', 'Cross-country child', 'DISTRICT')""").update())
                .isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("territory_parent_fk");
    }

    @Test
    void partnerUsersMustBelongToAPartnerOrg() {
        assertThatThrownBy(() -> app.sql("""
                INSERT INTO iam.user_account (external_subject, user_type, home_country_code, display_name)
                VALUES (gen_random_uuid(), 'PARTNER', 'IN', 'Orphan partner user')""").update())
                .isInstanceOf(DataIntegrityViolationException.class).hasMessageContaining("user_partner_matches_type");
    }

    @Test
    void auditTrailIsAppendOnlyForTheRuntimeRole() {
        app.sql("""
                INSERT INTO iam.audit_event (actor_user_id, action, target_type, target_id, outcome)
                VALUES (104, 'grant.create', 'GRANT', '5', 'SUCCESS')""").update();
        assertThatThrownBy(() -> app.sql("UPDATE iam.audit_event SET outcome = 'DENIED'").update())
                .isInstanceOf(DataAccessException.class).rootCause().hasMessageContaining("permission denied");
        assertThatThrownBy(() -> app.sql("DELETE FROM iam.audit_event").update())
                .isInstanceOf(DataAccessException.class).rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void runtimeRoleCannotRunDdl() {
        assertThatThrownBy(() -> app.sql("CREATE TABLE iam.evil (id int)").update())
                .isInstanceOf(DataAccessException.class).rootCause().hasMessageContaining("permission denied");
    }
}
