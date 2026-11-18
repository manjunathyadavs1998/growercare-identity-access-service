package com.growercare.iam.adapters.in.web;

import com.growercare.common.error.NotFoundException;
import com.growercare.iam.application.StaffContacts;
import java.util.List;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
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
    private final InternalAccess access;

    StaffContactController(StaffContacts contacts, InternalAccess access) {
        this.contacts = contacts;
        this.access = access;
    }

    /** R120/R121: `ids` is a comma-separated list of user ids (≤ 100). */
    @GetMapping("/users/names")
    List<StaffNameView> names(@RequestParam String ids) {
        // parsed by the service after the permission check: a non-staff caller always gets 403 (review)
        return contacts.names(ids).stream().map(s -> new StaffNameView(Long.toString(s.userId()), s.displayName())).toList();
    }

    /** R122/R123: only allow-listed contact clients (on top of the /internal/** service-token rule). */
    @GetMapping("/internal/users/by-id/{userId}/contact")
    ResponseEntity<ContactView> contact(@PathVariable String userId) {
        access.requireContactReader();
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
