package com.growercare.iam.adapters.in.web;

import com.growercare.common.error.NotFoundException;
import com.growercare.security.GcPrincipal;
import com.growercare.common.error.ValidationException;
import com.growercare.iam.application.port.PrincipalDirectory;
import java.util.UUID;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Service-to-service: other services resolve a Keycloak subject into a principal with effective grants.
 * Only reachable with a client-credentials token of an allow-listed client ({@code /internal/**} rule).
 */
@RestController
class InternalPrincipalController {

    private final PrincipalDirectory resolver;

    InternalPrincipalController(PrincipalDirectory resolver) {
        this.resolver = resolver;
    }

    @GetMapping("/internal/users/{subject}/principal")
    ResponseEntity<GcPrincipal> principal(@PathVariable UUID subject) {
        var principal = resolver.resolve(subject).orElseThrow(() -> new NotFoundException("User"));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(principal);
    }

    /** IAM-R18: assignee validation by user id; malformed id → 400, unknown/inactive → 404. */
    @GetMapping("/internal/users/by-id/{userId}/principal")
    ResponseEntity<GcPrincipal> principalById(@PathVariable String userId) {
        if (!userId.matches(IamDtos.ID)) {
            throw ValidationException.of("userId", "must be a positive numeric id");
        }
        var principal = resolver.resolveById(Long.parseLong(userId)).orElseThrow(() -> new NotFoundException("User"));
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(principal);
    }
}
