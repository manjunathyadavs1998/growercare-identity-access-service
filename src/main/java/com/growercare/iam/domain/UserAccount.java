package com.growercare.iam.domain;

import com.growercare.security.UserType;
import java.util.UUID;

/** iam.user_account row (no credentials: identity is proven by Keycloak). */
public record UserAccount(long userId, UUID subject, UserType userType, String homeCountry, Long partnerOrgId, String status) {

    public boolean isActive() {
        return "ACTIVE".equals(status);
    }
}
