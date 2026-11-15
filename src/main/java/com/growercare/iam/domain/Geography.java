package com.growercare.iam.domain;

import java.util.Map;
import java.util.Set;

/**
 * Geography facts needed to evaluate delegation: which country each requested territory is in, and which countries
 * each requested region contains.
 */
public record Geography(Map<Long, String> territoryCountry, Map<String, Set<String>> regionCountries) {

    public Geography {
        territoryCountry = Map.copyOf(territoryCountry);
        regionCountries = Map.copyOf(regionCountries);
    }
}
