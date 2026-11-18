package com.growercare.iam.adapters.in.web;

import com.growercare.common.error.NotFoundException;
import com.growercare.common.error.PermissionDeniedException;
import com.growercare.common.error.ValidationException;
import com.growercare.iam.application.StaffContacts;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import com.growercare.security.web.ServiceAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** SPEC-IAM-05: staff names for the UI and staff/partner contacts for notification-service. */
@RestController
class StaffContactController {

    record StaffNameView(String userId, String displayName) { }

    record ContactView(String userId, String email, String displayName, String language) { }

    private final StaffContacts contacts;
    private final Set<String> contactClients;

    StaffContactController(StaffContacts contacts, @Value("${gc.contact-clients}") String contactClients) {
        this.contacts = contacts;
        this.contactClients = Arrays.stream(contactClients.split(",")).map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    /** R120/R121: `ids` is a comma-separated list of user ids (≤ 100). */
    @GetMapping("/users/names")
    List<StaffNameView> names(@RequestParam String ids) {
        var parsed = new java.util.LinkedHashSet<Long>();
        for (var part : ids.split(",")) {
            var text = part.strip();
            if (text.isEmpty()) {
                continue;
            }
            parsed.add(parseId(text));
        }
        return contacts.names(List.copyOf(parsed)).stream().map(s -> new StaffNameView(Long.toString(s.userId()), s.displayName())).toList();
    }

    private static long parseId(String text) {
        if (!text.matches(IamDtos.ID)) {
            throw ValidationException.of("ids", "comma-separated positive ids");
        }
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw ValidationException.of("ids", "comma-separated positive ids");
        }
    }

    /** R122/R123: only allow-listed contact clients (on top of the /internal/** service-token rule). */
    @GetMapping("/internal/users/by-id/{userId}/contact")
    ResponseEntity<ContactView> contact(@PathVariable String userId) {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        // service tokens arrive as gc-security's ServiceAuthenticationToken; its principal is the client id
        String client = auth instanceof ServiceAuthenticationToken service ? String.valueOf(service.getPrincipal()) : null;
        if (client == null || !contactClients.contains(client)) {
            throw new PermissionDeniedException("contact");
        }
        if (!userId.matches(IamDtos.ID)) {
            throw new NotFoundException("User");
        }
        long id;
        try {
            id = Long.parseLong(userId);
        } catch (NumberFormatException e) {
            throw new NotFoundException("User");
        }
        var c = contacts.contact(id);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(new ContactView(Long.toString(c.userId()), c.email(), c.displayName(), "en"));
    }
}
