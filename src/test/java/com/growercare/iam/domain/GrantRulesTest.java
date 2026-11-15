package com.growercare.iam.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;

import com.growercare.common.error.BusinessRuleException;
import com.growercare.common.error.ConflictException;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.GcPrincipal;
import com.growercare.security.PiiClearance;
import com.growercare.security.ScopeKind;
import com.growercare.security.UserType;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** SPEC-IAM-01 unit examples IAM-U01…U10 ({@code docs/specs/iam/01-grant-administration.md}). */
class GrantRulesTest {

    static final Instant NOW = Instant.parse("2026-11-15T10:00:00Z");
    static final Geography GEO = new Geography(Map.of(1002L, "IN", 2002L, "BR"), Map.of("APAC", Set.of("IN")));

    static final GcPrincipal COUNTRY_ADMIN_IN = admin(60, ScopeKind.COUNTRY, Set.of("IN"));
    static final GcPrincipal GLOBAL_ADMIN = admin(90, ScopeKind.GLOBAL, Set.of());
    static final UserAccount STAFF_IN = user(102, UserType.STAFF, "ACTIVE");
    static final UserAccount ADMIN_SELF = user(104, UserType.STAFF, "ACTIVE");
    static final UserAccount GROWER_IN = user(1, UserType.GROWER, "ACTIVE");
    static final UserAccount SUSPENDED_IN = user(102, UserType.STAFF, "SUSPENDED");

    static final RoleDefinition CARE_AGENT = role("CARE_AGENT", 30, UserType.STAFF);
    static final RoleDefinition GLOBAL_PLATFORM_ADMIN = role("GLOBAL_PLATFORM_ADMIN", 90, UserType.STAFF);
    static final RoleDefinition GROWER = role("GROWER", 10, UserType.GROWER);
    static final RoleDefinition FINANCE_APPROVER = role("FINANCE_APPROVER", 45, UserType.STAFF);

    static final String ALLOWED = "allowed";
    static final String DUPLICATE_409 = "409 DUPLICATE";

    /** Columns: admin, target, role, geo, target's active roles, roles conflicting with the requested one, expected outcome. */
    static Stream<Arguments> grantExamples() {
        return Stream.of(
                argumentSet("IAM-U01a own country", COUNTRY_ADMIN_IN, STAFF_IN, CARE_AGENT, countries("IN"), Set.of(), Set.of(), ALLOWED),
                argumentSet("IAM-U01b territory inside own country", COUNTRY_ADMIN_IN, STAFF_IN, CARE_AGENT, territories(1002L), Set.of(), Set.of(), ALLOWED),
                argumentSet("IAM-U01c region whose countries are all covered", COUNTRY_ADMIN_IN, STAFF_IN, CARE_AGENT, regions("APAC"), Set.of(), Set.of(), ALLOWED),
                argumentSet("IAM-U02 role above own level", COUNTRY_ADMIN_IN, STAFF_IN, GLOBAL_PLATFORM_ADMIN, countries("IN"), Set.of(), Set.of(), "grant.delegation-level"),
                argumentSet("IAM-U03a other country", COUNTRY_ADMIN_IN, STAFF_IN, CARE_AGENT, countries("BR"), Set.of(), Set.of(), "grant.delegation-scope"),
                argumentSet("IAM-U03b territory of other country", COUNTRY_ADMIN_IN, STAFF_IN, CARE_AGENT, territories(2002L), Set.of(), Set.of(), "grant.delegation-scope"),
                argumentSet("IAM-U04 global admin covers any country", GLOBAL_ADMIN, STAFF_IN, CARE_AGENT, countries("BR"), Set.of(), Set.of(), ALLOWED),
                argumentSet("IAM-U05 self grant", COUNTRY_ADMIN_IN, ADMIN_SELF, CARE_AGENT, countries("IN"), Set.of(), Set.of(), "grant.self-grant"),
                argumentSet("IAM-U06 role not for this user type", COUNTRY_ADMIN_IN, STAFF_IN, GROWER, countries("IN"), Set.of(), Set.of(), "grant.user-type-mismatch"),
                argumentSet("IAM-U07 grower scope must be home country", COUNTRY_ADMIN_IN, GROWER_IN, GROWER, territories(1002L), Set.of(), Set.of(), "grant.scope-home-country"),
                argumentSet("IAM-U08 suspended target", COUNTRY_ADMIN_IN, SUSPENDED_IN, CARE_AGENT, countries("IN"), Set.of(), Set.of(), "grant.user-not-active"),
                argumentSet("IAM-U09 segregation of duties", COUNTRY_ADMIN_IN, STAFF_IN, FINANCE_APPROVER, countries("IN"), Set.of("FINANCE_ANALYST"), Set.of("FINANCE_ANALYST"), "grant.sod-conflict"),
                argumentSet("IAM-U10 already holds role", COUNTRY_ADMIN_IN, STAFF_IN, CARE_AGENT, countries("IN"), Set.of("CARE_AGENT"), Set.of(), DUPLICATE_409));
    }

    @ParameterizedTest
    @MethodSource("grantExamples")
    void grantRules(GcPrincipal admin, UserAccount target, RoleDefinition role, GeoScopeRequest geo,
                    Set<String> activeRoles, Set<String> conflicts, String expected) {
        var command = new CreateGrantCommand(target.userId(), role.roleCode(), geo, Set.of(), null, "spec example");
        assertThat(outcome(() -> GrantRules.checkCreate(admin, NOW, target, role, command, activeRoles, conflicts, GEO)))
                .isEqualTo(expected);
    }

    /** Columns: viewer, permission, target, expected visibility. */
    static Stream<Arguments> administrationVisibility() {
        return Stream.of(
                argumentSet("IAM-R5 own country", COUNTRY_ADMIN_IN, "grant:create", STAFF_IN, true),
                argumentSet("IAM-R5 other country", COUNTRY_ADMIN_IN, "grant:create", user(105, UserType.STAFF, "ACTIVE", "BR"), false),
                argumentSet("IAM-R4 permission not held", COUNTRY_ADMIN_IN, "user:manage", STAFF_IN, false),
                argumentSet("IAM-R5 global admin", GLOBAL_ADMIN, "grant:create", user(105, UserType.STAFF, "ACTIVE", "BR"), true));
    }

    @ParameterizedTest
    @MethodSource("administrationVisibility")
    void administrationVisibilityFollowsCountryScope(GcPrincipal viewer, String permission, UserAccount target, boolean visible) {
        assertThat(GrantRules.canAdminister(viewer, NOW, permission, target)).isEqualTo(visible);
    }

    // ---------------------------------------------------------------------------------------------- fixtures

    private static String outcome(Runnable rules) {
        try {
            rules.run();
            return ALLOWED;
        } catch (BusinessRuleException e) {
            return e.rule();
        } catch (ConflictException e) {
            return "409 " + e.code().name();
        }
    }

    static GcPrincipal admin(int level, ScopeKind kind, Set<String> countries) {
        var grant = new EffectiveGrant(7, "COUNTRY_ADMIN", level, kind, PiiClearance.MASKED,
                Set.of("grant:create", "grant:revoke", "grant:read"), countries, Set.of(), Set.of(), null);
        return new GcPrincipal(104, UUID.randomUUID(), UserType.STAFF, "IN", null, List.of(grant));
    }

    static UserAccount user(long id, UserType type, String status) {
        return user(id, type, status, "IN");
    }

    static UserAccount user(long id, UserType type, String status, String country) {
        return new UserAccount(id, UUID.randomUUID(), type, country, null, status);
    }

    static RoleDefinition role(String code, int level, UserType type) {
        return new RoleDefinition(code, level, ScopeKind.COUNTRY, type, false);
    }

    static GeoScopeRequest countries(String... codes) {
        return new GeoScopeRequest(Set.of(), Set.of(codes), Set.of());
    }

    static GeoScopeRequest territories(Long... ids) {
        return new GeoScopeRequest(Set.of(), Set.of(), Set.of(ids));
    }

    static GeoScopeRequest regions(String... codes) {
        return new GeoScopeRequest(Set.of(codes), Set.of(), Set.of());
    }
}
