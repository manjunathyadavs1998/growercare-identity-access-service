package com.growercare.iam;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.OpenApiContract;
import com.growercare.testsupport.PostgresTestDatabase;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;

/** SPEC-PLAT-01 R1/R3, examples PLAT-E20/E22 for identity-access-service. */
@SpringBootTest(properties = {"springdoc.api-docs.enabled=true"})
@AutoConfigureMockMvc
@Import(IamSecurityIT.Tokens.class)
class IamOpenApiContractIT {

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

    @Autowired
    MockMvc mvc;

    JsonNode api() throws Exception {
        return OpenApiContract.parse(mvc.perform(get("/v3/api-docs")).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString());
    }

    static Stream<Arguments> operations() {
        return Stream.of(
                argumentSet("PLAT-E20a GET /me", "/me", "get"),
                argumentSet("PLAT-E20b POST /grants", "/grants", "post"),
                argumentSet("PLAT-E20c DELETE /grants/{grantId}", "/grants/{grantId}", "delete"),
                argumentSet("PLAT-E20d GET /users/{userId}/grants", "/users/{userId}/grants", "get"));
    }

    @ParameterizedTest
    @MethodSource("operations")
    void documentedOperation(String path, String method) throws Exception {
        assertThat(OpenApiContract.hasOperation(api(), path, method)).as("%s %s documented", method, path).isTrue();
    }

    @Test
    void platE22BearerSchemeAndContractExport() throws Exception {
        var api = api();
        assertThat(api.path("components").path("securitySchemes").path("bearer").path("scheme").asString()).isEqualTo("bearer");
        assertThat(api.path("security").toString()).contains("bearer");
        assertThat(OpenApiContract.export(api, "identity-access-service")).exists();
    }
}
