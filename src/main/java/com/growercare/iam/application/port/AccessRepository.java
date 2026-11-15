package com.growercare.iam.application.port;

import com.growercare.iam.domain.GeoScopeRequest;
import com.growercare.iam.domain.RoleDefinition;
import com.growercare.iam.domain.StoredGrant;
import com.growercare.iam.domain.UserAccount;
import com.growercare.security.EffectiveGrant;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/** Persistence port for users, roles and grants (implemented with hand-written SQL, ADR-013). */
public interface AccessRepository {

    Optional<UserAccount> findUserBySubject(UUID subject);

    Optional<UserAccount> findUser(long userId);

    Optional<RoleDefinition> findRole(String roleCode);

    /** Active grants of the user, resolved: permissions, countries (incl. regions), territories (incl. descendants), BUs. */
    List<EffectiveGrant> effectiveGrants(long userId);

    Set<String> activeRoleCodes(long userId);

    Set<String> sodConflictsOf(String roleCode);

    Map<Long, String> territoryCountries(Set<Long> territoryIds);

    Map<String, Set<String>> regionCountries(Set<String> regionCodes);

    Set<String> existingCountries(Set<String> countryCodes);

    Set<String> existingRegions(Set<String> regionCodes);

    Set<String> existingBusinessUnits(Set<String> buCodes);

    /** Inserts the grant and its geo/BU scope rows; returns the stored grant. */
    StoredGrant insertGrant(long userId, String roleCode, GeoScopeRequest geo, Set<String> buCodes, Instant validTo,
                            long grantedBy, String reason);

    Optional<StoredGrant> findGrant(long grantId);

    List<StoredGrant> grantsOfUser(long userId);

    /** @return false when the grant was already revoked (concurrent revoke) */
    boolean revoke(long grantId, long revokedBy, String reason);
}
