package com.growercare.iam;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasItems;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.params.provider.Arguments.argumentSet;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.growercare.testsupport.PostgresTestDatabase;
import com.growercare.testsupport.TestJwts;
import java.util.List;
import java.util.UUID;
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
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** SPEC-IAM-04 R100–R106 (IAM-E100…E106): reference data and assignable staff for the UI. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(UiReferenceDataIT.Tokens.class)
class UiReferenceDataIT {

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

    ResultActions call(MockHttpServletRequestBuilder request, UUID as) throws Exception {
        return mvc.perform(request.header("Authorization", TestJwts.user(as).bearer()));
    }

    @Test
    void IAM_E100_aGrowerGetsTheTerritoriesOfTheirCountry() throws Exception {
        call(get("/reference/territories"), TestJwts.GROWER_IN1).andExpect(status().isOk())
                .andExpect(jsonPath("$[*].name", hasItems("Maharashtra", "Pune", "Nashik", "Bengaluru Rural")))
                .andExpect(jsonPath("$[?(@.territoryId == '1002')].parentTerritoryId", contains("1001")))
                .andExpect(jsonPath("$[?(@.territoryId == '1001')].level", contains("STATE")))
                .andExpect(jsonPath("$[0].level").value("STATE"));
    }

    static Stream<Arguments> otherCountries() {
        return Stream.of(
                argumentSet("IAM-E101 grower.in1 asks for Brazil", TestJwts.GROWER_IN1, "BR"),
                argumentSet("IAM-E101 care.in asks for Brazil", TestJwts.CARE_IN, "BR"),
                argumentSet("IAM-E101 an unknown country", TestJwts.CARE_IN, "XX"));
    }

    @ParameterizedTest
    @MethodSource("otherCountries")
    void countriesOutsideHomeAndGrantsAre404(UUID actor, String country) throws Exception {
        call(get("/reference/territories").param("country", country), actor).andExpect(status().isNotFound());
    }

    @Test
    void IAM_E102_rolesUpToTheAdminsLevel() throws Exception {
        call(get("/reference/roles"), TestJwts.ADMIN_IN).andExpect(status().isOk())
                .andExpect(jsonPath("$[*].roleCode", hasItems("CARE_AGENT", "FIELD_AGRONOMIST", "TERRITORY_MANAGER", "COUNTRY_ADMIN")))
                .andExpect(jsonPath("$[*].roleCode", not(hasItem("DPO"))))
                .andExpect(jsonPath("$[*].roleCode", not(hasItem("REGIONAL_ADMIN"))))
                .andExpect(jsonPath("$[*].roleCode", not(hasItem("GLOBAL_PLATFORM_ADMIN"))))
                .andExpect(jsonPath("$[?(@.roleCode == 'FIELD_AGRONOMIST')].scopeKind", contains("ASSIGNED")))
                .andExpect(jsonPath("$[?(@.roleCode == 'FIELD_AGRONOMIST')].allowedUserType", contains("STAFF")));
    }

    @Test
    void IAM_E103_rolesNeedGrantCreate() throws Exception {
        call(get("/reference/roles"), TestJwts.CARE_IN).andExpect(status().isForbidden());
    }

    @Test
    void IAM_E104_staffWhoCouldTakeAPuneCase() throws Exception {
        call(get("/users/assignable").param("territoryId", "1002").param("buCode", "CP"), TestJwts.CARE_IN)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].userId", containsInAnyOrder("101", "102", "103")))
                .andExpect(jsonPath("$[?(@.userId == '102')].displayName", contains("Vikram Agro")))
                .andExpect(jsonPath("$[?(@.userId == '102')].roleCodes[*]", contains("FIELD_AGRONOMIST")))
                .andExpect(jsonPath("$[0].displayName").value("Anita Care"));
    }

    static Stream<Arguments> outOfScope() {
        return Stream.of(
                argumentSet("IAM-E105 an unknown territory", TestJwts.CARE_IN, "999999"),
                argumentSet("IAM-E105 outside tm.in's territories (Bengaluru Rural)", TestJwts.TM_IN, "1005"));
    }

    @ParameterizedTest
    @MethodSource("outOfScope")
    void territoriesOutsideTheAssignScopeAre404(UUID actor, String territoryId) throws Exception {
        call(get("/users/assignable").param("territoryId", territoryId).param("buCode", "CP"), actor)
                .andExpect(status().isNotFound());
    }

    static Stream<Arguments> withoutAssign() {
        return Stream.of(argumentSet("IAM-E106 agro.in", TestJwts.AGRO_IN), argumentSet("IAM-E106 grower.in1", TestJwts.GROWER_IN1));
    }

    @ParameterizedTest
    @MethodSource("withoutAssign")
    void assignableNeedsCaseAssign(UUID actor) throws Exception {
        call(get("/users/assignable").param("territoryId", "1002").param("buCode", "CP"), actor).andExpect(status().isForbidden());
    }

    @Test
    void IAM_E104_malformedParametersAre400() throws Exception {
        call(get("/users/assignable").param("territoryId", "abc").param("buCode", "CP"), TestJwts.CARE_IN).andExpect(status().isBadRequest());
        call(get("/users/assignable").param("territoryId", "1002"), TestJwts.CARE_IN).andExpect(status().isBadRequest());
    }
}
