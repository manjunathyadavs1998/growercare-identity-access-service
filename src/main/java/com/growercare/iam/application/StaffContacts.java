package com.growercare.iam.application;

import com.growercare.common.error.NotFoundException;
import com.growercare.common.error.PermissionDeniedException;
import com.growercare.common.error.ValidationException;
import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.application.port.UserDirectoryRepository;
import com.growercare.iam.application.port.UserDirectoryRepository.Contact;
import com.growercare.iam.application.port.UserDirectoryRepository.StaffName;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.ScopeKind;
import com.growercare.security.web.CurrentPrincipal;
import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** SPEC-IAM-05: staff names for the UI (R120/R121) and staff/partner contact for notification-service (R122). */
@Service
public class StaffContacts {

    static final int MAX_IDS = 100;
    private static final Set<String> READERS = Set.of("case:read", "dashboard:read");

    private final UserDirectoryRepository directory;
    private final AccessRepository access;
    private final Clock clock;

    public StaffContacts(UserDirectoryRepository directory, AccessRepository access, Clock clock) {
        this.directory = directory;
        this.access = access;
        this.clock = clock;
    }

    /** R120: for staff callers only: the STAFF among {@code ids} whose home country their case:read / dashboard:read grants cover. */
    @Transactional(readOnly = true)
    public List<StaffName> names(String rawIds) {
        var principal = CurrentPrincipal.require();
        if (principal.userType() != com.growercare.security.UserType.STAFF) {
            throw new PermissionDeniedException("case:read or dashboard:read (staff)");     // growers hold case:read too
        }
        var now = clock.instant();
        var grants = principal.grants().stream().filter(g -> g.isActiveAt(now) && READERS.stream().anyMatch(g::grants)).toList();
        if (grants.isEmpty()) {
            throw new PermissionDeniedException("case:read or dashboard:read");
        }
        // authorised first, then the input is checked: a non-staff caller always gets 403 (review)
        var ids = parseIds(rawIds == null ? "" : rawIds);
        if (ids.isEmpty() || ids.size() > MAX_IDS) {
            throw ValidationException.of("ids", "between 1 and " + MAX_IDS + " ids");
        }
        boolean global = grants.stream().anyMatch(g -> g.scopeKind() == ScopeKind.GLOBAL);
        var countries = new HashSet<String>();
        for (EffectiveGrant g : grants) {
            countries.addAll(g.countries());
            if (!g.territories().isEmpty()) {
                countries.addAll(access.territoryCountries(g.territories()).values());
            }
        }
        return directory.staffNames(ids).stream().filter(s -> global || countries.contains(s.homeCountry())).toList();
    }

    /** Comma-separated positive ids, duplicates dropped; anything else is a 400 on {@code ids}. */
    static Set<Long> parseIds(String raw) {
        var ids = new java.util.LinkedHashSet<Long>();
        for (var part : raw.split(",")) {
            var text = part.strip();
            if (text.isEmpty()) {
                continue;
            }
            if (!text.matches("^[1-9][0-9]{0,18}$")) {
                throw ValidationException.of("ids", "comma-separated positive ids");
            }
            try {
                ids.add(Long.parseLong(text));
            } catch (NumberFormatException e) {
                throw ValidationException.of("ids", "comma-separated positive ids");
            }
        }
        return ids;
    }

    /** R122: ACTIVE staff or partner users with an email; growers, inactive, unknown and email-less users are 404. */
    @Transactional(readOnly = true)
    public Contact contact(long userId) {
        return directory.contact(userId)
                .filter(c -> "ACTIVE".equals(c.status()) && ("STAFF".equals(c.userType()) || "PARTNER".equals(c.userType())))
                .filter(c -> c.email() != null && !c.email().isBlank())         // nothing to send to: same as unknown
                .orElseThrow(() -> new NotFoundException("User"));
    }
}
