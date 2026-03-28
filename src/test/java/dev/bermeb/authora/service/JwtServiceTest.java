package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.security.UserPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    AuthoraProperties properties;
    @InjectMocks
    JwtService jwtService;

    private UserPrincipal principal;

    @BeforeEach
    void setup() {
        AuthoraProperties.Jwt jwt = new AuthoraProperties.Jwt();
        jwt.setSecret("testSecretKeyForJwtThatIsLongEnoughForHS256Algorithm123");
        jwt.setAccessTokenExpirationMinutes(15);
        jwt.setIssuer("test-issuer");
        when(properties.getJwt()).thenReturn(jwt);

        User user = User.builder()
                .id(UUID.randomUUID())
                .email("u@example.com")
                .roles(Set.of(Role.USER))
                .build();
        principal = UserPrincipal.of(user);
    }

    @Test
    @DisplayName("generated token should contain correct subject")
    void generateToken_hasCorrectSubject() {
        String token = jwtService.generateAccessToken(principal);
        assertThat(jwtService.extractUsername(token)).isEqualTo("u@example.com");
    }

    @Test
    @DisplayName("token should be valid for the correct user")
    void tokenIsValidForCorrectUser() {
        String token = jwtService.generateAccessToken(principal);
        assertThat(jwtService.isTokenValid(token, principal)).isTrue();
    }

    @Test
    @DisplayName("token should not be valid for a different user")
    void tokenIsInvalidForDifferentUser() {
        String token = jwtService.generateAccessToken(principal);

        User other = User.builder()
                .id(UUID.randomUUID())
                .email("other@example.com")
                .roles(Set.of(Role.USER))
                .build();
        UserPrincipal otherPrincipal = UserPrincipal.of(other);

        assertThat(jwtService.isTokenValid(token, otherPrincipal)).isFalse();
    }

    @Test
    @DisplayName("tampered token should be invalid")
    void tamperedToken_isInvalid() {
        String token = jwtService.generateAccessToken(principal);
        String tampered = token.substring(0, token.length() - 5) + "XXXXX";
        assertThat(jwtService.isTokenValid(tampered, principal)).isFalse();
    }
}