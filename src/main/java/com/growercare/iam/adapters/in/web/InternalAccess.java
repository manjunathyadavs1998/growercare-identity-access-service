package com.growercare.iam.adapters.in.web;

import com.growercare.common.error.PermissionDeniedException;
import com.growercare.security.web.ServiceAuthenticationToken;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * SPEC-IAM-05 D2a (least privilege): gc-security admits every GC_INTERNAL_CLIENTS service token on /internal/**; each
 * internal route group then has its own allow-list: principal resolution (grants) for the services that authorise
 * users, contacts (emails) for the sender. notification-service reads emails and nothing else.
 */
@Component
class InternalAccess {

    private final Set<String> principalClients;
    private final Set<String> contactClients;

    InternalAccess(@Value("${gc.principal-clients}") String principalClients, @Value("${gc.contact-clients}") String contactClients) {
        this.principalClients = parse(principalClients);
        this.contactClients = parse(contactClients);
    }

    void requirePrincipalReader() {
        require(principalClients, "principal");
    }

    void requireContactReader() {
        require(contactClients, "contact");
    }

    private static void require(Set<String> allowed, String what) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        String client = auth instanceof ServiceAuthenticationToken service ? String.valueOf(service.getPrincipal()) : null;
        if (client == null || !allowed.contains(client)) {
            throw new PermissionDeniedException(what);
        }
    }

    private static Set<String> parse(String clients) {
        return Arrays.stream(clients.split(",")).map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }
}
