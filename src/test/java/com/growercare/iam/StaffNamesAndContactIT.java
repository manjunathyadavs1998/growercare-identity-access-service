package com.growercare.iam;

import static org.hamcrest.Matchers.contains;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.PostgresTestDatabase;
import com.growercare.testsupport.TestJwts;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.LongStream;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

/** SPEC-IAM-05 R120–R123 (IAM-E120…E123): staff names for the UI, staff contact for notification-service. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(StaffNamesAndContactIT.Tokens.class)
class StaffNamesAndContactIT {

    static final PostgresTestDatabase DB = PostgresTestDatabase.forService("gc_iam");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("spring.datasource.url", DB::jdbcUrl);
        r.add("spring.datasource.username", DB::appUser);
        r.add("spring.datasource.password", DB::appPassword);
        r.add("spring.flyway.user", DB::ownerUser);
        r.add("spring.flyway.password", DB::ownerPassword);
        r.add("spring.flyway.locations", () -> "classpath:db/migration,classpath:db/dev-seed");
    }

    @TestConfiguration
    static class Tokens {
        @Bean
        @Primary
        JwtDecoder testJwtDecoder() {
            return TestJwts.decoder(List.of("gc-api", "gc-internal"));
        }
    }

    @Autowired
    MockMvc mvc;

    /** Test-only: a global executive (dashboard:read, GLOBAL scope; IAM-E120). */
    static final UUID GLOBAL_EXEC = UUID.fromString("6f1c0a10-0966-4a00-8000-000000000966");

    /** Test-only users: an ACTIVE staff user without an email (IAM-E122) and a global executive (IAM-E120). */
    @org.junit.jupiter.api.BeforeEach
    void testUsers() {
        var owner = org.springframework.jdbc.core.simple.JdbcClient.create(DB.ownerDataSource());
        owner.sql("""
                INSERT INTO iam.user_account (user_id, external_subject, user_type, home_country_code, display_name)
                VALUES (965, '6f1c0a10-0965-4a00-8000-000000000965', 'STAFF', 'IN', 'No Mail Staff') ON CONFLICT DO NOTHING""").update();
        owner.sql("""
                INSERT INTO iam.user_account (user_id, external_subject, user_type, home_country_code, display_name, email)
                VALUES (966, ?, 'STAFF', 'IN', 'Global Exec', 'exec.test@growercare.test') ON CONFLICT DO NOTHING""").param(GLOBAL_EXEC).update();
        owner.sql("INSERT INTO iam.role_grant (grant_id, user_id, role_code, grant_reason) VALUES (966, 966, 'GLOBAL_EXECUTIVE', 'test: IAM-E120') ON CONFLICT DO NOTHING").update();
        owner.sql("""
                INSERT INTO iam.user_account (user_id, external_subject, user_type, home_country_code, display_name, email, status)
                VALUES (967, '6f1c0a10-0967-4a00-8000-000000000967', 'STAFF', 'IN', 'Suspended Staff', 'suspended.test@growercare.test', 'SUSPENDED')
                ON CONFLICT DO NOTHING""").update();
    }

    ResultActions call(String path, String bearer) throws Exception {
        return mvc.perform(get(path).header("Authorization", bearer));
    }

    static Stream<Arguments> named() {
        return Stream.of(
                argumentSet("IAM-E120 tm.in: only Indian staff (1 is a grower, 105 is Brazilian)", TestJwts.TM_IN, "102,1,105", new String[] {"102"}, "Vikram Agro"),
                argumentSet("IAM-E120 care.in with case:read", TestJwts.CARE_IN, "101,103", new String[] {"101", "103"}, "Anita Care"),
                argumentSet("IAM-E120 a GLOBAL dashboard reader sees staff of every country", GLOBAL_EXEC, "102,105", new String[] {"102", "105"}, "Vikram Agro"));
    }

    @ParameterizedTest
    @MethodSource("named")
    void onlyStaffInTheCallersCountriesAreNamed(UUID actor, String ids, String[] expected, String firstName) throws Exception {
        call("/users/names?ids=" + ids, TestJwts.user(actor).bearer()).andExpect(status().isOk())
                .andExpect(jsonPath("$[*].userId", contains((Object[]) expected)))
                .andExpect(jsonPath("$[0].displayName").value(firstName));
    }

    static Stream<Arguments> refusedNames() {
        var tooMany = LongStream.rangeClosed(1, 101).mapToObj(Long::toString).collect(Collectors.joining(","));
        return Stream.of(
                argumentSet("IAM-E121 a grower (holds case:read, but is not staff)", TestJwts.GROWER_IN1, "102", 403),
                argumentSet("IAM-E121 more than 100 ids", TestJwts.TM_IN, tooMany, 400),
                argumentSet("IAM-E121 a malformed id", TestJwts.TM_IN, "abc", 400),
                argumentSet("IAM-E121 a grower with a malformed id is still 403 (authorised first)", TestJwts.GROWER_IN1, "abc", 403),
                argumentSet("IAM-E121 staff with neither permission (admin.in: user:read, no case:read)", TestJwts.ADMIN_IN, "102", 403),
                argumentSet("IAM-E121 a grower without ids is still 403 (authorised first)", TestJwts.GROWER_IN1, "", 403));
    }

    @ParameterizedTest
    @MethodSource("refusedNames")
    void refusedNameLookups(UUID actor, String ids, int expected) throws Exception {
        call("/users/names?ids=" + ids, TestJwts.user(actor).bearer()).andExpect(status().is(expected));
    }

    static Stream<Arguments> contacts() {
        return Stream.of(
                argumentSet("IAM-E122 agro.in (staff)", "102", 200, "agro.in@growercare.test", "Vikram Agro"),
                argumentSet("IAM-E122 retailer.in (partner)", "201", 200, "retailer.in@growercare.test", "Suresh (Patil Agro Store)"),
                argumentSet("IAM-E122 a grower", "1", 404, null, null),
                argumentSet("IAM-E122 unknown", "999999", 404, null, null),
                argumentSet("IAM-E122 malformed", "abc", 404, null, null),
                argumentSet("IAM-E122 staff without an email", "965", 404, null, null),
                argumentSet("IAM-E122 a suspended staff user", "967", 404, null, null));
    }

    @ParameterizedTest
    @MethodSource("contacts")
    void notificationServiceReadsStaffAndPartnerContacts(String userId, int expected, String email, String name) throws Exception {
        var result = call("/internal/users/by-id/" + userId + "/contact", TestJwts.service("notification-service").bearer())
                .andExpect(status().is(expected));
        if (expected == 200) {
            result.andExpect(jsonPath("$.email").value(email)).andExpect(jsonPath("$.displayName").value(name))
                    .andExpect(jsonPath("$.language").value("en")).andExpect(jsonPath("$.phone").doesNotExist());
        }
    }

    static Stream<Arguments> refusedContacts() {
        return Stream.of(
                argumentSet("IAM-E123 an end-user token", (Supplier<String>) () -> TestJwts.user(TestJwts.CARE_IN).bearer()),
                argumentSet("IAM-E123 an internal client that may not read contacts", (Supplier<String>) () -> TestJwts.service("case-service").bearer()));
    }

    @ParameterizedTest
    @MethodSource("refusedContacts")
    void onlyContactClientsReadContacts(Supplier<String> bearer) throws Exception {
        call("/internal/users/by-id/102/contact", bearer.get()).andExpect(status().isForbidden());
    }

    static Stream<Arguments> principalRoutes() {
        return Stream.of(
                argumentSet("IAM-E124 by subject", "/internal/users/" + TestJwts.CARE_IN + "/principal"),
                argumentSet("IAM-E124 by id", "/internal/users/by-id/102/principal"));
    }

    /** SPEC-IAM-05 D2a: the sender reads emails and never resolves principals with grants. */
    @ParameterizedTest
    @MethodSource("principalRoutes")
    void theSenderCannotResolvePrincipals(String path) throws Exception {
        call(path, TestJwts.service("notification-service").bearer()).andExpect(status().isForbidden());
    }
}
