package com.growercare.iam.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.growercare.common.error.BusinessRuleException;
import com.growercare.common.error.ValidationException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** SPEC-IAM-03 R62/R63 (IAM-E62, E63): phone, country and name rules. */
class SelfRegistrationRulesTest {

    @ParameterizedTest(name = "IAM-E62 username \"{0}\" is a phone: {1}")
    @CsvSource(nullValues = "NULL", textBlock = """
            +919811122233,  true
            +5516991234455, true
            919811122233,   false
            +0911122233,    false
            asha,           false
            NULL,           false
            """)
    void usernamesMustBeE164(String username, boolean phone) {
        if (phone) {
            assertThat(SelfRegistrationRules.phone(username)).isEqualTo(username);
        } else {
            assertThatThrownBy(() -> SelfRegistrationRules.phone(username)).isInstanceOf(BusinessRuleException.class)
                    .satisfies(e -> assertThat(((BusinessRuleException) e).rule()).isEqualTo("iam.username-not-phone"));
        }
    }

    @ParameterizedTest(name = "IAM-E62 {0} in calling code {1}: {2}")
    @CsvSource(textBlock = """
            +919811122233,  91, true
            +5516991234455, 55, true
            +5516991234455, 91, false
            +919811122233,  55, false
            """)
    void thePhoneMustBelongToTheCountry(String phone, String callingCode, boolean matches) {
        if (matches) {
            SelfRegistrationRules.requireCallingCode(phone, callingCode);
        } else {
            assertThatThrownBy(() -> SelfRegistrationRules.requireCallingCode(phone, callingCode))
                    .isInstanceOf(BusinessRuleException.class);
        }
    }

    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> names() {
        return java.util.stream.Stream.of(
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 an ordinary name", "Asha Pawar", true),
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 surrounding spaces are stripped", "  Asha  ", true),
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 120 characters (the limit)", "a".repeat(120), true),
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 121 characters", "a".repeat(121), false),
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 a control character", "A\u0000", false),
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 blank", "   ", false),
                org.junit.jupiter.params.provider.Arguments.argumentSet("IAM-E63 empty", "", false));
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("names")
    void displayNames(String name, boolean valid) {
        if (valid) {
            assertThat(SelfRegistrationRules.displayName(name)).isEqualTo(name.strip());
        } else {
            assertThatThrownBy(() -> SelfRegistrationRules.displayName(name)).isInstanceOf(ValidationException.class);
        }
    }
}
