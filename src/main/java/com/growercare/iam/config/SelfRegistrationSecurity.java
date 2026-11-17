package com.growercare.iam.config;

import com.growercare.security.web.GcSecurityProperties;
import com.growercare.security.web.ProblemSecurityHandlers;
import java.util.List;
import java.util.Optional;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;

/**
 * SPEC-IAM-03 D2: the one route an end user may call before having an IAM account. Its own chain, ahead of
 * gc-security's (which needs a resolved principal for every user route): a valid token (signature, issuer, audience
 * via the shared JwtDecoder) whose audience includes the API audience. Service-client tokens get no authority (403).
 */
@Configuration(proxyBeanMethods = false)
public class SelfRegistrationSecurity {

    static final String SELF_REGISTRANT = "ROLE_SELF_REGISTRANT";

    @Bean
    @Order(1)
    SecurityFilterChain selfRegistrationChain(HttpSecurity http, GcSecurityProperties props, ProblemSecurityHandlers problems)
            throws Exception {
        http.securityMatcher("/self-registration")
                // bearer tokens only, no cookies or sessions: there is no browser credential a forged request could ride on
                .csrf(c -> c.ignoringRequestMatchers("/self-registration"))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(a -> a.anyRequest().hasAuthority(SELF_REGISTRANT))
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(token -> {
                            var audiences = Optional.ofNullable(token.getAudience()).orElse(List.of());
                            var authorities = audiences.contains(props.apiAudience())
                                    ? List.of(new SimpleGrantedAuthority(SELF_REGISTRANT)) : List.<SimpleGrantedAuthority>of();
                            return new JwtAuthenticationToken(token, authorities);
                        }))
                        .authenticationEntryPoint(problems)
                        .accessDeniedHandler(problems))
                .exceptionHandling(e -> e.authenticationEntryPoint(problems).accessDeniedHandler(problems));
        return http.build();
    }
}
