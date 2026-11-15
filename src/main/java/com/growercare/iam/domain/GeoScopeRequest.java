package com.growercare.iam.domain;

import java.util.Set;

/** Requested geography of a grant: any mix of regions, countries and territories (each row exactly one level). */
public record GeoScopeRequest(Set<String> regionCodes, Set<String> countryCodes, Set<Long> territoryIds) {

    public GeoScopeRequest {
        regionCodes = regionCodes == null ? Set.of() : Set.copyOf(regionCodes);
        countryCodes = countryCodes == null ? Set.of() : Set.copyOf(countryCodes);
        territoryIds = territoryIds == null ? Set.of() : Set.copyOf(territoryIds);
    }

    public boolean isEmpty() {
        return regionCodes.isEmpty() && countryCodes.isEmpty() && territoryIds.isEmpty();
    }

    /** True for "exactly this one country and nothing else". */
    public boolean isExactlyCountry(String countryCode) {
        return regionCodes.isEmpty() && territoryIds.isEmpty() && countryCodes.equals(Set.of(countryCode));
    }
}
