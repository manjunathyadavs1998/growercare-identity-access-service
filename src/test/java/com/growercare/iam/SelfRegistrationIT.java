package com.growercare.iam;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.PostgresTestDatabase;
import com.growercare.testsupport.TestJwts;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.json.JsonMapper;

/** SPEC-IAM-03 R60–R67 (IAM-E60…E68): grower self-registration on the first call after Keycloak sign-up. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(SelfRegistrationIT.Tokens.class)
class SelfRegistrationIT {

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

    /** Keycloak puts the username (the phone) into {@code preferred_username}; tests register it per subject. */
    static final Map<String, String> USERNAMES = new ConcurrentHashMap<>();
    static final AtomicLong NEXT_PHONE = new AtomicLong(9_811_100_000L);

    @TestConfiguration
    static class Tokens {
        @Bean
        @Primary
        JwtDecoder testJwtDecoder() {
            var delegate = TestJwts.decoder(List.of("gc-api", "gc-internal"));
            return token -> {
                Jwt jwt = delegate.decode(token);
                var username = USERNAMES.get(jwt.getSubject());
                if (username == null) {
                    return jwt;
                }
                return Jwt.withTokenValue(jwt.getTokenValue()).headers(h -> h.putAll(jwt.getHeaders()))
                        .claims(c -> {
                            c.putAll(jwt.getClaims());
                            c.put("preferred_username", username);
                        }).build();
            };
        }
    }

    static final JsonMapper JSON = JsonMapper.builder().build();

    @Autowired
    MockMvc mvc;

    final JdbcClient owner = JdbcClient.create(DB.ownerDataSource());

    /** A Keycloak user that has just signed up with this username. */
    static UUID newSubject(String username) {
        var subject = UUID.randomUUID();
        if (username != null) {
            USERNAMES.put(subject.toString(), username);
        }
        return subject;
    }

    static String indianPhone() {
        return "+91" + NEXT_PHONE.getAndIncrement();
    }

    ResultActions register(String authorization, String country, String name) throws Exception {
        var request = post("/self-registration").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("countryCode", country, "displayName", name)));
        if (authorization != null) {
            request.header("Authorization", authorization);
        }
        return mvc.perform(request);
    }

    static ResultActions problem(ResultActions r, int status, String code) throws Exception {
        return r.andExpect(status().is(status))
                .andExpect(header().string("Content-Type", "application/problem+json"))
                .andExpect(jsonPath("$.code").value(code));
    }

    @Test
    void IAM_E60_E66_aNewGrowerGetsAnAccountAndCanUseItAtOnce() throws Exception {
        var phone = indianPhone();
        var subject = newSubject(phone);
        var token = TestJwts.user(subject).bearer();
        mvc.perform(get("/me").header("Authorization", token)).andExpect(status().isUnauthorized());          // IAM-E65

        register(token, "IN", "Asha Pawar").andExpect(status().isCreated())
                .andExpect(jsonPath("$.userType").value("GROWER"))
                .andExpect(jsonPath("$.homeCountry").value("IN"))
                .andExpect(jsonPath("$.grants.length()").value(1))
                .andExpect(jsonPath("$.grants[0].roleCode").value("GROWER"));
        mvc.perform(get("/me").header("Authorization", token)).andExpect(status().isOk());                    // IAM-E66

        var row = owner.sql("SELECT user_type || ':' || home_country_code || ':' || phone_last4 || ':' || display_name FROM iam.user_account WHERE external_subject = ?")
                .param(subject).query(String.class).single();
        assertThat(row).isEqualTo("GROWER:IN:" + phone.substring(phone.length() - 4) + ":Asha Pawar");
        var grant = owner.sql("SELECT g.role_code || ':' || coalesce(g.granted_by_user_id::text, 'system') || ':' || g.grant_reason || ':' || s.country_code"
                        + " FROM iam.role_grant g JOIN iam.grant_geo_scope s ON s.grant_id = g.grant_id"
                        + " JOIN iam.user_account u ON u.user_id = g.user_id WHERE u.external_subject = ?")
                .param(subject).query(String.class).single();
        assertThat(grant).isEqualTo("GROWER:system:self-registration:IN");
        var events = owner.sql("SELECT payload::text FROM iam.outbox WHERE event_type = 'iam.grant.created' AND payload -> 'data' ->> 'subject' = ?")
                .param(subject.toString()).query(String.class).list();
        assertThat(events).singleElement().satisfies(e -> assertThat(e).doesNotContain(phone.substring(3), "Asha"));
    }

    @Test
    void IAM_E61_registeringAgainIsIdempotentButTheCountryIsFixed() throws Exception {
        var subject = newSubject(indianPhone());
        var token = TestJwts.user(subject).bearer();
        var first = register(token, "IN", "Ravi").andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String userId = com.jayway.jsonpath.JsonPath.read(first, "$.userId");
        register(token, "IN", "Ravi").andExpect(status().isOk()).andExpect(jsonPath("$.userId").value(userId));
        problem(register(token, "BR", "Ravi"), 409, "DUPLICATE");
    }

    static Stream<Arguments> refused() {
        return Stream.of(
                argumentSet("IAM-E62 Brazilian phone, India chosen", "+5516991230000", "IN", "iam.phone-country-mismatch"),
                argumentSet("IAM-E62 unknown country", "+919811199999", "XX", "iam.country-unavailable"),
                argumentSet("IAM-E62 username is not a phone", "asha", "IN", "iam.username-not-phone"),
                argumentSet("IAM-E62 no username claim", null, "IN", "iam.username-not-phone"));
    }

    @ParameterizedTest
    @MethodSource("refused")
    void phoneAndCountryMustMatch(String username, String country, String rule) throws Exception {
        var subject = newSubject(username);
        problem(register(TestJwts.user(subject).bearer(), country, "Test"), 422, "BUSINESS_RULE_VIOLATION")
                .andExpect(jsonPath("$.rule").value(rule));
        assertThat(owner.sql("SELECT count(*) FROM iam.user_account WHERE external_subject = ?").param(subject).query(Long.class).single()).isZero();
    }

    static Stream<Arguments> invalidNames() {
        return Stream.of(argumentSet("IAM-E63 blank", "  "), argumentSet("IAM-E63 121 characters", "a".repeat(121)),
                argumentSet("IAM-E63 control character", "A\u0000"));
    }

    @ParameterizedTest
    @MethodSource("invalidNames")
    void invalidDisplayNamesAre400(String name) throws Exception {
        problem(register(TestJwts.user(newSubject(indianPhone())).bearer(), "IN", name), 400, "VALIDATION_FAILED")
                .andExpect(jsonPath("$.errors[0].field").value("displayName"));
    }

    static Stream<Arguments> callers() {
        return Stream.of(
                argumentSet("IAM-E64 no token", null, 401),
                argumentSet("IAM-E64 forged token", TestJwts.user(UUID.randomUUID()).forgedSignature().bearer(), 401),
                argumentSet("IAM-E64 a service-client token", TestJwts.service("case-service").bearer(), 403));
    }

    @ParameterizedTest
    @MethodSource("callers")
    void onlyEndUserTokensMayRegister(String authorization, int expected) throws Exception {
        register(authorization, "IN", "Test").andExpect(status().is(expected));
    }

    static Stream<Arguments> blocked() {
        return Stream.of(
                argumentSet("IAM-E68 suspended, same country", "SUSPENDED", "IN"),
                argumentSet("IAM-E68 suspended, another country (no 409 that would reveal IN)", "SUSPENDED", "BR"),
                argumentSet("IAM-E68 deactivated, same country", "DEACTIVATED", "IN"));
    }

    @ParameterizedTest
    @MethodSource("blocked")
    void aBlockedAccountIsNeverRevived(String accountStatus, String country) throws Exception {
        var subject = newSubject(indianPhone());
        var token = TestJwts.user(subject).bearer();
        register(token, "IN", "Blocked Grower").andExpect(status().isCreated());
        owner.sql("UPDATE iam.user_account SET status = ? WHERE external_subject = ?").params(accountStatus, subject).update();
        problem(register(token, country, "Blocked Grower"), 403, "PERMISSION_DENIED");
    }
}
