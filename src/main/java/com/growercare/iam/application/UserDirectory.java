package com.growercare.iam.application;

import com.growercare.common.error.NotFoundException;
import com.growercare.common.error.ValidationException;
import com.growercare.common.paging.Cursor;
import com.growercare.iam.application.port.AccessRepository;
import com.growercare.iam.application.port.UserDirectoryRepository;
import com.growercare.iam.application.port.UserDirectoryRepository.DirectoryUser;
import com.growercare.iam.domain.StoredGrant;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.GcPrincipal;
import com.growercare.security.PiiClearance;
import com.growercare.security.RequiresPermission;
import com.growercare.security.ScopeKind;
import com.growercare.security.web.CurrentPrincipal;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * SPEC-IAM-02: the read-only user directory. Visibility is the grant-administration rule (D2: the user's home country
 * inside the admin's {@code user:read} countries, or a GLOBAL grant); grower names follow the admin's clearance (D3, D6).
 */
@Service
public class UserDirectory {

    public static final String PERM_USER_READ = "user:read";
    static final String ID = "^[1-9][0-9]{0,18}$";

    public record Page(List<DirectoryUser> items, String nextCursor) { }

    /** R81: a user with their active grants (D5). */
    public record UserWithGrants(DirectoryUser user, List<StoredGrant> grants) { }

    public record Query(String q, String userType, String country, String status, String cursor, int limit) { }

    private final UserDirectoryRepository directory;
    private final AccessRepository access;
    private final Clock clock;

    public UserDirectory(UserDirectoryRepository directory, AccessRepository access, Clock clock) {
        this.directory = directory;
        this.access = access;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    @RequiresPermission(PERM_USER_READ)
    public Page search(Query query) {
        var viewer = CurrentPrincipal.require();
        var grants = viewer.grantsWith(PERM_USER_READ, clock.instant()).toList();
        long after = query.cursor() == null ? 0 : Cursor.decode(query.cursor());
        String prefix = null;
        Long qUserId = null;
        if (query.q() != null) {
            var q = query.q().strip();
            if (q.matches(ID)) {
                qUserId = parseOrNull(q);
            } else if (q.codePointCount(0, q.length()) < 2) {
                throw ValidationException.of("q", "needs at least 2 characters or a user id");
            }
            prefix = q.toLowerCase(Locale.ROOT);
        }
        var search = new UserDirectoryRepository.Search(
                grants.stream().anyMatch(g -> g.scopeKind() == ScopeKind.GLOBAL), countries(grants, false),
                grants.stream().anyMatch(g -> g.scopeKind() == ScopeKind.GLOBAL && g.piiClearance() == PiiClearance.FULL), countries(grants, true),
                query.country(), query.userType(), query.status(), prefix, qUserId, after, query.limit() + 1);
        var rows = directory.search(search).stream().map(u -> masked(viewer, u)).toList();
        if (rows.size() > query.limit()) {
            var page = rows.subList(0, query.limit());
            return new Page(page, Cursor.encode(page.getLast().userId()));
        }
        return new Page(rows, null);
    }

    @Transactional(readOnly = true)
    @RequiresPermission(PERM_USER_READ)
    public UserWithGrants user(long userId) {
        var viewer = CurrentPrincipal.require();
        var now = clock.instant();
        var user = directory.user(userId)
                .filter(u -> visible(viewer, now, u.homeCountry()))
                .orElseThrow(() -> new NotFoundException("User"));
        var active = access.grantsOfUser(userId).stream().filter(g -> isActive(g, now)).toList();
        return new UserWithGrants(masked(viewer, user), active);
    }

    // ------------------------------------------------------------------------------------------------ rules

    /** D2: same as {@code GrantRules.canAdminister} for {@code user:read}. */
    private static boolean visible(GcPrincipal viewer, Instant now, String country) {
        return viewer.grantsWith(PERM_USER_READ, now)
                .anyMatch(g -> g.scopeKind() == ScopeKind.GLOBAL || g.countries().contains(country));
    }

    /** D3: a grower's name is shown only under a FULL-clearance {@code user:read} grant covering their country. */
    private DirectoryUser masked(GcPrincipal viewer, DirectoryUser u) {
        if (!"GROWER".equals(u.userType())) {
            return u;
        }
        boolean full = viewer.grantsWith(PERM_USER_READ, clock.instant())
                .anyMatch(g -> g.piiClearance() == PiiClearance.FULL
                        && (g.scopeKind() == ScopeKind.GLOBAL || g.countries().contains(u.homeCountry())));
        return full ? u : new DirectoryUser(u.userId(), u.userType(), u.homeCountry(), u.partnerOrgId(), maskName(u.displayName()),
                u.phoneLast4(), u.status());
    }

    private static Set<String> countries(List<EffectiveGrant> grants, boolean fullOnly) {
        var countries = new HashSet<String>();
        grants.stream().filter(g -> !fullOnly || g.piiClearance() == PiiClearance.FULL).forEach(g -> countries.addAll(g.countries()));
        return countries;
    }

    private static boolean isActive(StoredGrant g, Instant now) {
        return g.revokedAt() == null && !g.validFrom().isAfter(now) && (g.validTo() == null || g.validTo().isAfter(now));
    }

    /** "Ramesh Patil" → "R***** P****" (as case-service CASE-R30 and grower-service). */
    static String maskName(String name) {
        if (name == null || name.isEmpty()) {
            return name;
        }
        return Arrays.stream(name.split(" ", -1))
                .map(word -> word.isEmpty() ? word : word.charAt(0) + "*".repeat(word.length() - 1))
                .collect(Collectors.joining(" "));
    }

    private static Long parseOrNull(String digits) {
        try {
            return Long.parseLong(digits);
        } catch (NumberFormatException e) {
            return null;                    // 19 digits above Long.MAX_VALUE: no such user, but still a name search
        }
    }
}
