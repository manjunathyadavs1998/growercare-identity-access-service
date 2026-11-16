package com.growercare.iam;

import static com.growercare.testsupport.TestJwts.ADMIN_IN;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.EventContracts;
import com.growercare.testsupport.PostgresTestDatabase;
import com.growercare.testsupport.TestJwts;
import com.jayway.jsonpath.JsonPath;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** SPEC-PLAT-04 R54 / E63: IAM's grant events, produced by the real API, match their contracts. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(IamSecurityIT.Tokens.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamEventContractIT {

    static final PostgresTestDatabase DB = PostgresTestDatabase.forService("gc_iam");

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        IamSecurityIT.props(r);
    }

    @Autowired
    MockMvc mvc;

    @BeforeAll
    void grantAndRevoke() throws Exception {
        var json = mvc.perform(post("/grants").header("Authorization", TestJwts.user(ADMIN_IN).bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"userId":"103","roleCode":"QUALITY_INVESTIGATOR","countryCodes":["IN"],"buCodes":["CP"],"reason":"Contract check"}"""))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String grantId = JsonPath.read(json, "$.grantId");
        mvc.perform(delete("/grants/{id}", grantId).param("reason", "Contract check done")
                        .header("Authorization", TestJwts.user(ADMIN_IN).bearer()))
                .andExpect(status().isOk());
    }

    static Stream<Arguments> eventTypes() {
        return Stream.of("iam.grant.created", "iam.grant.revoked").map(type -> argumentSet("PLAT-E63 " + type, type));
    }

    @ParameterizedTest
    @MethodSource("eventTypes")
    void everyOutboxRowMatchesItsContract(String eventType) {
        var envelopes = JdbcClient.create(DB.ownerDataSource())
                .sql("SELECT payload::text FROM iam.outbox WHERE event_type = ?").param(eventType)
                .query(String.class).list();

        assertThat(envelopes).isNotEmpty();
        List<String> problems = envelopes.stream().flatMap(e -> EventContracts.violations(eventType, e).stream()).distinct().toList();
        assertThat(problems).isEmpty();
    }
}
