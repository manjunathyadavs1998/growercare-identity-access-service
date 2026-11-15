package com.growercare.iam.domain;

import com.growercare.common.error.BusinessRuleException;
import com.growercare.common.error.ConflictException;
import com.growercare.common.error.ErrorCode;
import com.growercare.security.EffectiveGrant;
import com.growercare.security.GcPrincipal;
import com.growercare.security.ScopeKind;
import com.growercare.security.UserType;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Pure rules for granting and revoking roles (BRD §4: ACC-1, ACC-2, ACC-6). No I/O: all facts are passed in,
 * so every rule is unit-testable. Violations throw {@link BusinessRuleException} with a stable {@code rule} id.
 */
public final class GrantRules {

    public static final String PERM_GRANT_CREATE = "grant:create";
    public static final String PERM_GRANT_REVOKE = "grant:revoke";
    public static final String PERM_GRANT_READ = "grant:read";

    private GrantRules() { }

    /** Throws when {@code admin} may not grant {@code role} to {@code target} as requested. */
    public static void checkCreate(GcPrincipal admin, Instant now, UserAccount target, RoleDefinition role,
                                   CreateGrantCommand cmd, Set<String> targetActiveRoles, Set<String> conflictingRoles,
                                   Geography geography) {
        if (admin.userId() == target.userId()) {
            throw new BusinessRuleException("grant.self-grant", "Administrators cannot grant roles to themselves");
        }
        if (!target.isActive()) {
            throw new BusinessRuleException("grant.user-not-active", "The user account is not active");
        }
        if (role.allowedUserType() != target.userType()) {
            throw new BusinessRuleException("grant.user-type-mismatch",
                    "Role " + role.roleCode() + " cannot be granted to a " + target.userType() + " user");
        }
        if (target.userType() != UserType.STAFF && !cmd.geo().isExactlyCountry(target.homeCountry())) {
            throw new BusinessRuleException("grant.scope-home-country",
                    "Grower and partner grants must be scoped to exactly the user's home country");
        }
        checkDelegation(admin, now, PERM_GRANT_CREATE, role, cmd.geo(), geography);
        var conflict = conflictingRoles.stream().filter(targetActiveRoles::contains).sorted().findFirst();
        if (conflict.isPresent()) {
            throw new BusinessRuleException("grant.sod-conflict",
                    "Role " + role.roleCode() + " conflicts with the user's active role " + conflict.get());
        }
        if (targetActiveRoles.contains(role.roleCode())) {
            throw new ConflictException(ErrorCode.DUPLICATE, "The user already holds an active " + role.roleCode() + " grant");
        }
    }

    /**
     * Delegation (ACC-2): some active grant of the admin holding {@code permission} must have a role level ≥ the
     * target role's level, and every requested region / country / territory must be covered by such grants.
     */
    public static void checkDelegation(GcPrincipal admin, Instant now, String permission, RoleDefinition role,
                                       GeoScopeRequest geo, Geography geography) {
        List<EffectiveGrant> strongEnough = admin.grantsWith(permission, now)
                .filter(g -> g.roleLevel() >= role.roleLevel())
                .toList();
        if (strongEnough.isEmpty()) {
            throw new BusinessRuleException("grant.delegation-level",
                    "Role " + role.roleCode() + " is above the administrator's own level");
        }
        boolean allCovered = Stream.of(
                        geo.countryCodes().stream().map(c -> covered(strongEnough, g -> g.countries().contains(c))),
                        geo.territoryIds().stream().map(t -> covered(strongEnough,
                                g -> g.territories().contains(t) || g.countries().contains(geography.territoryCountry().get(t)))),
                        geo.regionCodes().stream().map(r -> covered(strongEnough, g -> {
                            var countries = geography.regionCountries().getOrDefault(r, Set.of());
                            return !countries.isEmpty() && g.countries().containsAll(countries);
                        })))
                .flatMap(s -> s)
                .allMatch(Boolean::booleanValue);
        if (!allCovered) {
            throw new BusinessRuleException("grant.delegation-scope",
                    "The requested scope is outside the administrator's own scope");
        }
    }

    /** May {@code viewer} see/administer users of {@code target}'s home country with {@code permission}? */
    public static boolean canAdminister(GcPrincipal viewer, Instant now, String permission, UserAccount target) {
        return viewer.grantsWith(permission, now)
                .anyMatch(g -> g.scopeKind() == ScopeKind.GLOBAL || g.countries().contains(target.homeCountry()));
    }

    private static boolean covered(List<EffectiveGrant> grants, java.util.function.Predicate<EffectiveGrant> covers) {
        return grants.stream().anyMatch(g -> g.scopeKind() == ScopeKind.GLOBAL || covers.test(g));
    }
}
