package com.growercare.iam.domain;

import com.growercare.common.error.ValidationException;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/** Grant {@code roleCode} to {@code targetUserId} within {@code geo} / {@code buCodes} (empty = all BUs) until {@code validTo}. */
public record CreateGrantCommand(
        long targetUserId,
        String roleCode,
        GeoScopeRequest geo,
        Set<String> buCodes,
        Instant validTo,
        String reason) {

    public CreateGrantCommand {
        Objects.requireNonNull(roleCode, "roleCode");
        Objects.requireNonNull(geo, "geo");
        buCodes = buCodes == null ? Set.of() : Set.copyOf(buCodes);
        if (geo.isEmpty()) {
            throw ValidationException.of("geo", "at least one region, country or territory is required");
        }
        if (reason == null || reason.isBlank()) {
            throw ValidationException.of("reason", "must not be blank");
        }
    }
}
