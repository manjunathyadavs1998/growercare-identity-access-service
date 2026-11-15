package com.growercare.iam.domain;

import java.time.Instant;
import java.util.Set;

/** A role_grant row with its raw (unexpanded) scope. */
public record StoredGrant(
        long grantId,
        long userId,
        String roleCode,
        Instant validFrom,
        Instant validTo,
        Long grantedByUserId,
        Instant revokedAt,
        GeoScopeRequest geo,
        Set<String> buCodes) {

    public StoredGrant {
        buCodes = Set.copyOf(buCodes);
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }
}
