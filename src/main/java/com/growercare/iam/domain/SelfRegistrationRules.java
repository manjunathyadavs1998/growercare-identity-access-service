package com.growercare.iam.domain;

import com.growercare.common.error.BusinessRuleException;
import com.growercare.common.error.ValidationException;
import java.util.regex.Pattern;

/** SPEC-IAM-03 R62/R63: what a self-registration must satisfy. Framework-free. */
public final class SelfRegistrationRules {

    private SelfRegistrationRules() { }

    public static final int MAX_NAME = 120;
    public static final String ROLE = "GROWER";
    public static final String REASON = "self-registration";

    private static final Pattern E164 = Pattern.compile("^\\+[1-9][0-9]{7,14}$");
    private static final Pattern COUNTRY = Pattern.compile("^[A-Z]{2}$");
    private static final Pattern CONTROL = Pattern.compile("[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}&&[^\\u200C\\u200D]]");

    /** R62: the Keycloak username must be a phone number in E.164 (SPEC-IAM-03 D1). */
    public static String phone(String username) {
        if (username == null || !E164.matcher(username).matches()) {
            throw new BusinessRuleException("iam.username-not-phone", "The account's username is not a phone number");
        }
        return username;
    }

    /** R62: the phone's calling code must be the country's (D4). */
    public static void requireCallingCode(String phone, String callingCode) {
        if (!phone.startsWith("+" + callingCode)) {
            throw new BusinessRuleException("iam.phone-country-mismatch", "The phone number does not belong to the chosen country");
        }
    }

    public static String countryCode(String raw) {
        if (raw == null || !COUNTRY.matcher(raw).matches()) {
            throw ValidationException.of("countryCode", "must be an ISO 3166-1 alpha-2 code, e.g. IN");
        }
        return raw;
    }

    /** R63: 1–120 characters without control characters, checked before stripping (as SPEC-GRW-01 R15). */
    public static String displayName(String raw) {
        if (raw == null || CONTROL.matcher(raw).find() || raw.strip().isEmpty() || raw.strip().length() > MAX_NAME) {
            throw ValidationException.of("displayName", "must be 1-" + MAX_NAME + " characters without control characters");
        }
        return raw.strip();
    }

    public static String lastFour(String phone) {
        return phone.substring(phone.length() - 4);
    }
}
