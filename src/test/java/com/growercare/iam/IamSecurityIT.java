package com.growercare.iam;

import static com.growercare.testsupport.TestJwts.ADMIN_IN;
import static com.growercare.testsupport.TestJwts.AGRO_IN;
import static com.growercare.testsupport.TestJwts.CARE_IN;
import static com.growercare.testsupport.TestJwts.GROWER_IN1;
import static com.growercare.testsupport.TestJwts.TM_IN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.PostgresTestDatabase;
import com.growercare.testsupport.TestJwts;
import com.jayway.jsonpath.JsonPath;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
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
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * SPEC-IAM-01 over HTTP ({@code docs/specs/iam/01-grant-administration.md}); test names carry the spec example IDs.
 * Real PostgreSQL with the owner/app role split; tokens minted by {@link TestJwts}.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(IamSecurityIT.Tokens.class)   // explicit: nested @TestConfiguration is not detected for @Nested classes (Spring 7)
class IamSecurityIT {

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

    final JdbcClient owner = JdbcClient.create(DB.ownerDataSource());

    ResultActions call(MockHttpServletRequestBuilder request, UUID as) throws Exception {
        return mvc.perform(request.header("Authorization", TestJwts.user(as).bearer()));
    }

    ResultActions grant(UUID as, String json) throws Exception {
        return call(post("/grants").contentType(MediaType.APPLICATION_JSON).content(json), as);
    }

    static ResultActions problem(ResultActions r, int status, String code) throws Exception {
        return r.andExpect(status().is(status))
                .andExpect(header().string("Content-Type", "application/problem+json"))
                .andExpect(jsonPath("$.code").value(code))
                .andExpect(jsonPath("$.traceId").value(notNullValue()))
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.exception").doesNotExist());
    }

    @Nested
    class Authentication {

        /** IAM-E01 / E02: the Authorization header value (null = absent). */
        static Stream<Arguments> invalidCredentials() {
            return Stream.of(
                    argumentSet("IAM-E01a no token", (Supplier<String>) () -> null),
                    argumentSet("IAM-E01b forged signature", (Supplier<String>) () -> TestJwts.user(CARE_IN).forgedSignature().bearer()),
                    argumentSet("IAM-E01c expired", (Supplier<String>) () -> TestJwts.user(CARE_IN).expiresAt(Instant.now().minusSeconds(120)).bearer()),
                    argumentSet("IAM-E01d wrong audience", (Supplier<String>) () -> TestJwts.user(CARE_IN).audience("some-other-api").bearer()),
                    argumentSet("IAM-E01e foreign issuer", (Supplier<String>) () -> TestJwts.user(CARE_IN).issuer("https://evil.example/realms/growercare").bearer()),
                    argumentSet("IAM-E02 valid token, no account", (Supplier<String>) () -> TestJwts.user(UUID.randomUUID()).bearer()));
        }

        @ParameterizedTest
        @MethodSource("invalidCredentials")
        void invalidCredentialsAre401(Supplier<String> authorization) throws Exception {
            var request = get("/me");
            var header = authorization.get();
            if (header != null) {
                request.header("Authorization", header);
            }
            problem(mvc.perform(request), 401, "UNAUTHENTICATED").andExpect(header().string("WWW-Authenticate", "Bearer"));
        }

        @Test
        void healthIsPublic() throws Exception {
            mvc.perform(get("/actuator/health")).andExpect(status().isOk());
        }

        @org.junit.jupiter.params.ParameterizedTest(name = "PLAT-R2 {0} is not exposed by default")
        @org.junit.jupiter.params.provider.ValueSource(strings = {"/v3/api-docs", "/swagger-ui/index.html"})
        void apiDocsAreNotExposedByDefault(String path) throws Exception {
            problem(mvc.perform(get(path)), 401, "UNAUTHENTICATED");
        }
    }

    @Nested
    class EffectiveGrants {

        @Test
        void iamE03TerritoryHierarchyIsExpanded() throws Exception {
            call(get("/me"), TM_IN).andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value("103"))
                    .andExpect(jsonPath("$.grants[0].roleCode").value("TERRITORY_MANAGER"))
                    .andExpect(jsonPath("$.grants[0].territoryIds", hasItems("1001", "1002", "1003")))
                    .andExpect(jsonPath("$.grants[0].territoryIds", not(hasItem("1005"))))
                    .andExpect(jsonPath("$.grants[0].permissions", hasItem("case:assign")));
        }

        @Test
        void iamE04ExpiredGrantsAreNotEffective() throws Exception {
            owner.sql("""
                    INSERT INTO iam.role_grant (user_id, role_code, valid_from, valid_to, granted_by_user_id, grant_reason)
                    VALUES (102, 'STEWARDSHIP_OFFICER', now() - interval '2 days', now() - interval '1 day', 104, 'expired test grant')""").update();
            call(get("/me"), AGRO_IN).andExpect(status().isOk())
                    .andExpect(jsonPath("$.grants[*].roleCode", not(hasItem("STEWARDSHIP_OFFICER"))));
        }
    }

    @Nested
    class InternalApi {

        /** IAM-E19: Authorization header, expected status, expected problem code (null = success). */
        static Stream<Arguments> internalCallers() {
            return Stream.of(
                    argumentSet("IAM-E19a allow-listed service", (Supplier<String>) () -> TestJwts.service("case-service").bearer(), 200, null),
                    argumentSet("IAM-E19b unknown service client", (Supplier<String>) () -> TestJwts.service("unknown-client").bearer(), 401, "UNAUTHENTICATED"),
                    argumentSet("IAM-E19c end-user token", (Supplier<String>) () -> TestJwts.user(ADMIN_IN).bearer(), 403, "PERMISSION_DENIED"));
        }

        @ParameterizedTest
        @MethodSource("internalCallers")
        void internalApiAccess(Supplier<String> authorization, int status, String code) throws Exception {
            var result = mvc.perform(get("/internal/users/{s}/principal", CARE_IN).header("Authorization", authorization.get()));
            if (code == null) {
                result.andExpect(status().isOk()).andExpect(jsonPath("$.grants[0].roleCode").value("CARE_AGENT"));
            } else {
                problem(result, status, code);
            }
        }

        /** IAM-E20 (R18): user id, expected status, expected role (200) or problem code. */
        static Stream<Arguments> principalsById() {
            return Stream.of(
                    argumentSet("IAM-E20a active staff user", "102", 200, "FIELD_AGRONOMIST"),
                    argumentSet("IAM-E20b unknown user", "999", 404, "NOT_FOUND"),
                    argumentSet("IAM-E20c malformed id", "abc", 400, "VALIDATION_FAILED"));
        }

        @ParameterizedTest
        @MethodSource("principalsById")
        void principalByUserId(String userId, int status, String expected) throws Exception {
            var result = mvc.perform(get("/internal/users/by-id/{id}/principal", userId)
                    .header("Authorization", TestJwts.service("case-service").bearer()));
            if (status == 200) {
                result.andExpect(status().isOk()).andExpect(jsonPath("$.grants[0].roleCode").value(expected));
            } else {
                problem(result, status, expected);
            }
        }

        @Test
        void iamR17ServiceTokensCannotCallUserApis() throws Exception {
            problem(mvc.perform(get("/me").header("Authorization", TestJwts.service("case-service").bearer())), 403, "PERMISSION_DENIED");
        }
    }

    @Nested
    class GrantAdministration {

        /** IAM-E05…E16: actor, request body, expected status, problem code, 422 rule (or 400 field) or null. */
        static Stream<Arguments> rejectedRequests() {
            return Stream.of(
                    argumentSet("IAM-E05 no grant:create", CARE_IN,
                            "{\"userId\":\"102\",\"roleCode\":\"CARE_AGENT\",\"countryCodes\":[\"IN\"],\"reason\":\"x\"}", 403, "PERMISSION_DENIED", null),
                    argumentSet("IAM-E07 user outside admin country", ADMIN_IN,
                            "{\"userId\":\"105\",\"roleCode\":\"QUALITY_INVESTIGATOR\",\"countryCodes\":[\"BR\"],\"reason\":\"x\"}", 404, "NOT_FOUND", null),
                    argumentSet("IAM-E08 role above own level", ADMIN_IN,
                            "{\"userId\":\"102\",\"roleCode\":\"GLOBAL_PLATFORM_ADMIN\",\"countryCodes\":[\"IN\"],\"reason\":\"x\"}", 422, "BUSINESS_RULE_VIOLATION", "grant.delegation-level"),
                    argumentSet("IAM-E09 scope outside own scope", ADMIN_IN,
                            "{\"userId\":\"102\",\"roleCode\":\"CARE_AGENT\",\"countryCodes\":[\"BR\"],\"reason\":\"x\"}", 422, "BUSINESS_RULE_VIOLATION", "grant.delegation-scope"),
                    argumentSet("IAM-E10 self grant", ADMIN_IN,
                            "{\"userId\":\"104\",\"roleCode\":\"QUALITY_INVESTIGATOR\",\"countryCodes\":[\"IN\"],\"reason\":\"x\"}", 422, "BUSINESS_RULE_VIOLATION", "grant.self-grant"),
                    argumentSet("IAM-E11 role for another user type", ADMIN_IN,
                            "{\"userId\":\"102\",\"roleCode\":\"GROWER\",\"countryCodes\":[\"IN\"],\"reason\":\"x\"}", 422, "BUSINESS_RULE_VIOLATION", "grant.user-type-mismatch"),
                    argumentSet("IAM-E12 duplicate active role", ADMIN_IN,
                            "{\"userId\":\"101\",\"roleCode\":\"CARE_AGENT\",\"countryCodes\":[\"IN\"],\"reason\":\"again\"}", 409, "DUPLICATE", null),
                    argumentSet("IAM-E13 unknown role", ADMIN_IN,
                            "{\"userId\":\"101\",\"roleCode\":\"NOT_A_ROLE\",\"countryCodes\":[\"IN\"],\"reason\":\"x\"}", 400, "VALIDATION_FAILED", "roleCode"),
                    argumentSet("IAM-E14 malformed country and blank reason", ADMIN_IN,
                            "{\"userId\":\"101\",\"roleCode\":\"CARE_AGENT\",\"countryCodes\":[\"india\"],\"reason\":\"\"}", 400, "VALIDATION_FAILED", null),
                    argumentSet("IAM-E15 no geo scope", ADMIN_IN,
                            "{\"userId\":\"101\",\"roleCode\":\"CARE_AGENT\",\"reason\":\"no scope\"}", 400, "VALIDATION_FAILED", "geo"),
                    argumentSet("IAM-E16 malformed JSON", ADMIN_IN, "{not json", 400, "VALIDATION_FAILED", null));
        }

        @ParameterizedTest
        @MethodSource("rejectedRequests")
        void rejectedRequests(UUID actor, String body, int status, String code, String detail) throws Exception {
            var result = problem(grant(actor, body), status, code);
            if (detail != null && status == 422) {
                result.andExpect(jsonPath("$.rule").value(detail));
            } else if (detail != null) {
                result.andExpect(jsonPath("$.errors[0].field").value(detail));
            }
        }

        /** IAM-E06: callers without the read permission. */
        static Stream<Arguments> readersWithoutPermission() {
            return Stream.of(
                    argumentSet("IAM-E06a grower", GROWER_IN1, "/users/1/grants"),
                    argumentSet("IAM-E06b care agent", CARE_IN, "/users/102/grants"));
        }

        @ParameterizedTest
        @MethodSource("readersWithoutPermission")
        void readingGrantsNeedsGrantRead(UUID actor, String path) throws Exception {
            problem(call(get(path), actor), 403, "PERMISSION_DENIED");
        }

        @Test
        void iamE17ValidGrantIsAuditedAndPublished() throws Exception {
            grant(ADMIN_IN, """
                    {"userId":"101","roleCode":"QUALITY_INVESTIGATOR","countryCodes":["IN"],"buCodes":["CP"],"reason":"Covering complaints backlog"}""")
                    .andExpect(status().isCreated())
                    .andExpect(header().string("Location", org.hamcrest.Matchers.startsWith("/grants/")))
                    .andExpect(jsonPath("$.roleCode").value("QUALITY_INVESTIGATOR"))
                    .andExpect(jsonPath("$.grantedByUserId").value("104"));

            call(get("/me"), CARE_IN).andExpect(jsonPath("$.grants[*].roleCode", hasItems("CARE_AGENT", "QUALITY_INVESTIGATOR")));
            assertThat(owner.sql("SELECT count(*) FROM iam.audit_event WHERE action = 'grant.create' AND outcome = 'SUCCESS' AND actor_user_id = 104")
                    .query(Integer.class).single()).isPositive();
            assertThat(owner.sql("SELECT count(*) FROM iam.outbox WHERE event_type = 'iam.grant.created' AND payload -> 'data' ->> 'userId' = '101'")
                    .query(Integer.class).single()).isEqualTo(1);
        }

        @Test
        void iamR15DenialsAreAuditedOutsideTheRolledBackTransaction() throws Exception {
            problem(grant(ADMIN_IN, """
                    {"userId":"102","roleCode":"GLOBAL_PLATFORM_ADMIN","countryCodes":["IN"],"reason":"audit check"}"""), 422, "BUSINESS_RULE_VIOLATION");
            assertThat(owner.sql("SELECT count(*) FROM iam.audit_event WHERE outcome = 'DENIED' AND reason = 'grant.delegation-level'")
                    .query(Integer.class).single()).isPositive();
        }

        @Test
        void iamE18SegregationOfDutiesThenRevocation() throws Exception {
            var analystGrantId = JsonPath.read(grant(ADMIN_IN, """
                    {"userId":"103","roleCode":"FINANCE_ANALYST","countryCodes":["IN"],"reason":"Month-end support"}""")
                    .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString(), "$.grantId").toString();

            problem(grant(ADMIN_IN, """
                    {"userId":"103","roleCode":"FINANCE_APPROVER","countryCodes":["IN"],"reason":"x"}"""), 422, "BUSINESS_RULE_VIOLATION")
                    .andExpect(jsonPath("$.rule").value("grant.sod-conflict"));

            problem(call(delete("/grants/{id}", analystGrantId).param("reason", "x"), CARE_IN), 403, "PERMISSION_DENIED");
            call(delete("/grants/{id}", analystGrantId).param("reason", "Month-end finished"), ADMIN_IN)
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.revokedAt").value(notNullValue()));
            problem(call(delete("/grants/{id}", analystGrantId).param("reason", "again"), ADMIN_IN), 422, "BUSINESS_RULE_VIOLATION")
                    .andExpect(jsonPath("$.rule").value("grant.already-revoked"));
            call(get("/me"), TM_IN).andExpect(jsonPath("$.grants[*].roleCode", not(hasItem("FINANCE_ANALYST"))));

            grant(ADMIN_IN, """
                    {"userId":"103","roleCode":"FINANCE_APPROVER","countryCodes":["IN"],"reason":"Approver rota"}""")
                    .andExpect(status().isCreated());
        }
    }
}
