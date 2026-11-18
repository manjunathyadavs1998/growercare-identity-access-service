package com.growercare.iam;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.PostgresTestDatabase;
import com.growercare.testsupport.TestJwts;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** SPEC-IAM-02 R80–R86 (IAM-E80…E85, E87): the user directory for administrators. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(UserDirectoryIT.Tokens.class)
class UserDirectoryIT {

    static final PostgresTestDatabase DB = PostgresTestDatabase.forService("gc_iam");

    /** Test-only: a data protection officer for India (user:read with FULL clearance). */
    static final UUID DPO_IN = UUID.fromString("6f1c0a10-0961-4a00-8000-000000000961");

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

    @BeforeAll
    static void dpo(@Autowired MockMvc ignored) {     // runs after the context (and Flyway) started
        var owner = JdbcClient.create(DB.ownerDataSource());
        owner.sql("""
                INSERT INTO iam.user_account (user_id, external_subject, user_type, home_country_code, display_name, email)
                VALUES (961, ?, 'STAFF', 'IN', 'Dev Privacy Officer', 'dpo.test@growercare.test') ON CONFLICT DO NOTHING""")
                .param(DPO_IN).update();
        owner.sql("""
                INSERT INTO iam.role_grant (grant_id, user_id, role_code, grant_reason) VALUES (961, 961, 'DPO', 'test: IAM-E87')
                ON CONFLICT DO NOTHING""").update();
        owner.sql("""
                INSERT INTO iam.grant_geo_scope (grant_id, country_code) VALUES (961, 'IN') ON CONFLICT DO NOTHING""").update();
    }

    ResultActions call(MockHttpServletRequestBuilder request, UUID as) throws Exception {
        return mvc.perform(request.header("Authorization", TestJwts.user(as).bearer()));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', textBlock = """
            IAM-E80 name prefix      | q=vik      | 102
            IAM-E80 staff of India   | type=STAFF | 104
            IAM-E80 exact user id    | q=102      | 102
            """)
    void adminFindsUsers(String name, String query, String expectedUserId) throws Exception {
        call(get("/users?" + query), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].userId", hasItem(expectedUserId)))
                .andExpect(jsonPath("$.items[*].homeCountry", everyItem(org.hamcrest.Matchers.is("IN"))))
                .andExpect(jsonPath("$.items[*].grants").doesNotExist());
    }

    @Test
    void IAM_E80_pagesFollowTheCursorByUserId() throws Exception {
        var first = call(get("/users?type=STAFF&limit=2"), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.items.length()").value(2)).andReturn().getResponse().getContentAsString();
        String cursor = com.jayway.jsonpath.JsonPath.read(first, "$.nextCursor");
        List<String> firstIds = com.jayway.jsonpath.JsonPath.read(first, "$.items[*].userId");
        call(get("/users?type=STAFF&limit=2").param("cursor", cursor), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.items[*].userId", not(hasItem(firstIds.get(0)))))
                .andExpect(jsonPath("$.items[*].userId", not(hasItem(firstIds.get(1)))));
    }

    @Test
    void IAM_E81_oneUserWithActiveGrants() throws Exception {
        call(get("/users/102"), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.displayName").value("Vikram Agro"))
                .andExpect(jsonPath("$.grants[*].roleCode", hasItem("FIELD_AGRONOMIST")))
                .andExpect(jsonPath("$.grants[*].revokedAt", everyItem(org.hamcrest.Matchers.nullValue())));
    }

    @ParameterizedTest(name = "IAM-E81 user {0} is not found")
    @CsvSource({"105", "999999", "abc", "99999999999999999999"})
    void invisibleOrUnknownUsersAre404(String userId) throws Exception {
        call(get("/users/{id}", userId), TestJwts.ADMIN_IN).andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }

    @Test
    void IAM_E82_growerNamesAreMaskedForAMaskedAdmin() throws Exception {
        call(get("/users?type=GROWER"), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.items[?(@.userId == '1')].displayName", contains("R***** P****")))
                .andExpect(jsonPath("$.items[?(@.userId == '2')].displayName", contains("S***** R**")))
                .andExpect(jsonPath("$.items[*].phone").doesNotExist())
                .andExpect(jsonPath("$.items[*].phoneHmac").doesNotExist());
        call(get("/users/1"), TestJwts.ADMIN_IN).andExpect(jsonPath("$.displayName").value("R***** P****"));
    }

    @Test
    void IAM_E83_anotherCountryGivesAnEmptyPage() throws Exception {
        call(get("/users?country=BR"), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.items.length()").value(0));
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(delimiter = '|', textBlock = """
            IAM-E84 q too short      | q=v        | q
            IAM-E84 unknown type     | type=ROBOT | type
            IAM-E84 unknown status   | status=GONE | status
            IAM-E84 malformed cursor | cursor=!!  | cursor
            """)
    void malformedSearchesAre400(String name, String query, String field) throws Exception {
        call(get("/users?" + query), TestJwts.ADMIN_IN).andExpect(status().isBadRequest())
                .andExpect(header().string("Content-Type", "application/problem+json"))
                .andExpect(jsonPath("$.errors[0].field").value(field));
    }

    static Stream<Arguments> withoutUserRead() {
        return Stream.of(
                argumentSet("IAM-E85 care.in", TestJwts.CARE_IN),
                argumentSet("IAM-E85 grower.in1", TestJwts.GROWER_IN1),
                argumentSet("IAM-E85 retailer.in", TestJwts.RETAILER_IN));
    }

    @ParameterizedTest
    @MethodSource("withoutUserRead")
    void noUserReadIs403(UUID actor) throws Exception {
        call(get("/users"), actor).andExpect(status().isForbidden());
        call(get("/users/102"), actor).andExpect(status().isForbidden());
    }

    static Stream<Arguments> nameSearch() {
        return Stream.of(
                argumentSet("IAM-E87 the DPO finds Ramesh by name, unmasked", DPO_IN, "q=ramesh", "Ramesh Patil"),
                argumentSet("IAM-E87 admin.in finds user 1 by id, masked", TestJwts.ADMIN_IN, "q=1", "R***** P****"));
    }

    @ParameterizedTest
    @MethodSource("nameSearch")
    void growerNamesFollowTheClearance(UUID actor, String query, String shown) throws Exception {
        call(get("/users?" + query), actor).andExpect(status().isOk())
                .andExpect(jsonPath("$.items[?(@.userId == '1')].displayName", contains(shown)));
    }

    @Test
    void IAM_E87_aMaskedAdminCannotSearchGrowerNames() throws Exception {
        call(get("/users?q=ramesh"), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$.items.length()").value(0));
    }
}
