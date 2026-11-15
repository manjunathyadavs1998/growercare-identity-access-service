package com.growercare.iam.application.port;

import com.growercare.security.GcPrincipal;
import com.growercare.security.PrincipalResolver;
import java.util.Optional;

/**
 * IAM's principal lookups (IAM-R17/R18): by Keycloak subject (via {@link PrincipalResolver}) and by IAM user id.
 * Inbound adapters depend on this port, never on the JDBC adapter (SPEC-PLAT-01 R6).
 */
public interface PrincipalDirectory extends PrincipalResolver {

    Optional<GcPrincipal> resolveById(long userId);
}
