package com.growercare.iam.application.port;

import java.util.List;

/** SPEC-IAM-04: read-only reference data for the UI. */
public interface ReferenceRepository {

    record Territory(long territoryId, Long parentTerritoryId, String code, String name, String level) { }

    record GrantableRole(String roleCode, String name, String scopeKind, String allowedUserType) { }

    /** One user and one of their qualifying roles. */
    record AssignableRow(long userId, String displayName, String roleCode) { }

    boolean countryExists(String country);

    List<Territory> territories(String country);

    List<GrantableRole> rolesUpTo(int level);

    List<AssignableRow> assignable(long territoryId, String country, String buCode);
}
