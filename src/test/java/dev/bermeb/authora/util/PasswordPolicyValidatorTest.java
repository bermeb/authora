package dev.bermeb.authora.util;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.AssertionsForClassTypes.assertThatCode;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class PasswordPolicyValidatorTest {

    @Mock
    AuthoraProperties properties;
    @InjectMocks
    PasswordPolicyValidator validator;

    @BeforeEach
    void setup() {
        AuthoraProperties.PasswordPolicy policy = new AuthoraProperties.PasswordPolicy();
        policy.setMinLength(12);
        policy.setRequireLowercase(true);
        policy.setRequireUppercase(true);
        policy.setRequireNumbers(true);
        policy.setRequireSpecialCharacters(true);
        when(properties.getPasswordPolicy()).thenReturn(policy);
    }

    @Test
    @DisplayName("validate password passes all checks")
    void valid_password() {
        assertThatCode(() -> validator.validate("ValidPass12!")).doesNotThrowAnyException();
    }

    @ParameterizedTest
    @DisplayName("weak passwords are rejected")
    @ValueSource(strings = {
            "short",
            "onlylowercase1!",
            "ONLYUPPERCASE1!",
            "NoNumberIncluded!",
            "NoSpecialCharIncluded234"
    })
    void weak_passwords_rejected(String password) {
        assertThatThrownBy(() -> validator.validate(password))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Password must contain");
    }
}