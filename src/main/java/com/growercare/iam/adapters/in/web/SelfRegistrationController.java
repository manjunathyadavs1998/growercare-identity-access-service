package com.growercare.iam.adapters.in.web;

import com.growercare.iam.adapters.in.web.IamDtos.MeView;
import com.growercare.iam.application.SelfRegistration;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * SPEC-IAM-03: {@code POST /self-registration}. Reached through its own security chain ({@code SelfRegistrationSecurity}):
 * a valid end-user token whose subject may not have an IAM account yet.
 */
@RestController
class SelfRegistrationController {

    /** Keycloak puts the username (the phone, D1) in this claim. */
    static final String USERNAME_CLAIM = "preferred_username";

    record SelfRegistrationRequest(String countryCode, String displayName) {
        @Override
        public String toString() {
            return "SelfRegistrationRequest[countryCode=%s]".formatted(countryCode);
        }
    }

    private final SelfRegistration registration;

    SelfRegistrationController(SelfRegistration registration) {
        this.registration = registration;
    }

    @PostMapping("/self-registration")
    ResponseEntity<MeView> register(JwtAuthenticationToken token, @RequestBody SelfRegistrationRequest body) {
        var jwt = token.getToken();
        UUID subject;
        try {
            subject = UUID.fromString(jwt.getSubject());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new InvalidBearerTokenException("Token subject is not a valid user id");
        }
        var result = registration.register(subject, jwt.getClaimAsString(USERNAME_CLAIM), body.countryCode(), body.displayName());
        return ResponseEntity.status(result.created() ? HttpStatus.CREATED : HttpStatus.OK).body(MeView.of(result.principal()));
    }
}
