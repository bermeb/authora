package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import dev.bermeb.authora.model.PasswordResetToken;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.PasswordResetTokenRepository;
import dev.bermeb.authora.repository.UserRepository;
import dev.bermeb.authora.util.PasswordPolicyValidator;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceTest {

    @Mock
    UserRepository userRepository;
    @Mock
    PasswordResetTokenRepository passwordResetTokenRepository;
    @Mock
    AuthenticationManager authManager;
    @Mock
    JwtService jwtService;
    @Mock
    RefreshTokenService refreshTokenService;
    @Mock
    EmailService emailService;
    @Mock
    AuditLogService auditLogService;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    PasswordPolicyValidator passwordPolicyValidator;
    @Mock
    AuthoraProperties properties;
    @Mock
    HttpServletRequest request;

    @InjectMocks
    AuthService authService;

    private User testUser;

    @BeforeEach
    void setup() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .passwordHash("$2a$12$hashed")
                .firstName("Jane")
                .lastName("Doe")
                .emailVerified(true)
                .enabled(true)
                .accountLocked(false)
                .failedLoginAttempts(0)
                .roles(Set.of(Role.USER))
                .build();

        // Default properties stubs
        AuthoraProperties.Features features = new AuthoraProperties.Features();
        features.setEmailVerificationRequired(false);
        features.setAuditLogEnabled(true);
        when(properties.getFeatures()).thenReturn(features);

        AuthoraProperties.RateLimit rateLimit = new AuthoraProperties.RateLimit();
        rateLimit.setMaxFailedAttempts(5);
        rateLimit.setLockDurationMinutes(15);
        when(properties.getRateLimit()).thenReturn(rateLimit);

        AuthoraProperties.RefreshToken rt = new AuthoraProperties.RefreshToken();
        rt.setRotateOnUse(true);
        when(properties.getRefreshToken()).thenReturn(rt);
    }

    @Nested
    @DisplayName("Registration")
    class Registration {

        @Test
        @DisplayName("should register a new user successfully")
        void register_success() {
            when(userRepository.existsByEmail(anyString())).thenReturn(false);
            when(passwordEncoder.encode(anyString())).thenReturn("$hashed");
            when(userRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            User result = authService.register("new@example.com", "ValidPass1!", "John", "Doe", request);

            assertThat(result.getEmail()).isEqualTo("new@example.com");
            assertThat(result.getRoles()).contains(Role.USER);
            verify(userRepository).save(any(User.class));
            verify(auditLogService).logSuccess(any(), any(), any());
        }

        @Test
        @DisplayName("should throw when email already registered")
        void register_duplicateEmail() {
            when(userRepository.existsByEmail(anyString())).thenReturn(true);

            assertThatThrownBy(() ->
                    authService.register("test@example.com", "pass", "A", "B", request)
            ).isInstanceOf(AuthException.class)
                    .hasMessageContaining("already registered");

            verify(userRepository, never()).save(any());
        }
    }

    @Nested
    @DisplayName("Login")
    class Login {

        @Test
        @DisplayName("should return tokens on valid credentials")
        void login_success() {
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));
            when(authManager.authenticate(any())).thenReturn(
                    new UsernamePasswordAuthenticationToken(
                            dev.bermeb.authora.security.UserPrincipal.of(testUser), null));
            when(jwtService.generateAccessToken(any())).thenReturn("access-token");
            when(refreshTokenService.createRefreshToken(any(), any())).thenReturn("refresh-token");
            when(jwtService.getAccessTokenExpirationSeconds()).thenReturn(900L);

            var result = authService.login("test@example.com", "password", request);

            assertThat(result).containsKey("accessToken");
            assertThat(result.get("accessToken")).isEqualTo("access-token");
            assertThat(result).containsKey("refreshToken");
        }

        @Test
        @DisplayName("should lock account after max failed attempts")
        void login_lockAfterMaxFailures() {
            testUser.setFailedLoginAttempts(4); // one more will lock
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));
            when(authManager.authenticate(any())).thenThrow(new BadCredentialsException("bad"));

            assertThatThrownBy(() ->
                    authService.login("test@example.com", "wrong", request)
            ).isInstanceOf(AuthException.class);

            assertThat(testUser.isAccountLocked()).isTrue();
            assertThat(testUser.getLockedUntil()).isNotNull();
        }

        @Test
        @DisplayName("should throw for unknown email")
        void login_unknownEmail() {
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

            assertThatThrownBy(() ->
                    authService.login("ghost@example.com", "pass", request)
            ).isInstanceOf(AuthException.class)
                    .hasMessageContaining("Invalid credentials");
        }

        @Test
        @DisplayName("should throw for locked account")
        void login_lockedAccount() {
            testUser.setAccountLocked(true);
            testUser.setLockedUntil(java.time.Instant.now().plusSeconds(600));
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));

            assertThatThrownBy(() ->
                    authService.login("test@example.com", "pass", request)
            ).isInstanceOf(AuthException.class)
                    .hasMessageContaining("locked");
        }
    }

    @Nested
    @DisplayName("Password Reset")
    class PasswordReset {

        @Test
        @DisplayName("requestPasswordReset should silently succeed for unknown email")
        void forgotPassword_unknownEmail_noError() {
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

            // Must NOT throw – prevents user enumeration
            assertThatCode(() ->
                    authService.requestPasswordReset("ghost@example.com", request)
            ).doesNotThrowAnyException();

            verify(emailService, never()).sendPasswordReset(any(), any());
        }

        @Test
        @DisplayName("requestPasswordReset should send email for known local user")
        void forgotPassword_knownUser_sendsEmail() {
            when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(testUser));
            when(passwordResetTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            AuthoraProperties.PasswordPolicy policy = new AuthoraProperties.PasswordPolicy();
            policy.setResetTokenExpiryMinutes(30);
            when(properties.getPasswordPolicy()).thenReturn(policy);

            authService.requestPasswordReset("test@example.com", request);

            verify(emailService).sendPasswordReset(eq(testUser), anyString());
        }
    }

    @Nested
    @DisplayName("Logout")
    class Logout {

        @Test
        @DisplayName("logout should revoke the refresh token")
        void logout_revokesToken() {
            authService.logout("raw-token", testUser, request);

            verify(refreshTokenService).revokeToken("raw-token");
            verify(auditLogService).logSuccess(any(), eq(testUser), any());
        }

        @Test
        @DisplayName("logoutAll should revoke all tokens")
        void logoutAll_revokesAll() {
            authService.logoutAll(testUser, request);

            verify(refreshTokenService).revokeAllForUser(testUser);
        }
    }

    @Nested
    @DisplayName("Refresh")
    class Refresh {

        @Test
        @DisplayName("with rotateOnUse=true rotates token and returns new access token")
        void refresh_withRotation() {
            when(refreshTokenService.getUserFromToken("rawToken")).thenReturn(testUser);
            when(refreshTokenService.rotateRefreshToken("rawToken", request)).thenReturn("newRawToken");
            when(jwtService.generateAccessToken(any())).thenReturn("newAccessToken");
            when(jwtService.getAccessTokenExpirationSeconds()).thenReturn(900L);

            Map<String, Object> result = authService.refresh("rawToken", request);

            assertThat(result.get("accessToken")).isEqualTo("newAccessToken");
            assertThat(result.get("refreshToken")).isEqualTo("newRawToken");
            verify(refreshTokenService).rotateRefreshToken("rawToken", request);
        }

        @Test
        @DisplayName("with rotateOnUse=false reuses the same refresh token")
        void refresh_withoutRotation() {
            properties.getRefreshToken().setRotateOnUse(false);
            when(refreshTokenService.getUserFromToken("rawToken")).thenReturn(testUser);
            when(jwtService.generateAccessToken(any())).thenReturn("newAccessToken");
            when(jwtService.getAccessTokenExpirationSeconds()).thenReturn(900L);

            Map<String, Object> result = authService.refresh("rawToken", request);

            assertThat(result.get("refreshToken")).isEqualTo("rawToken");
            verify(refreshTokenService, never()).rotateRefreshToken(any(), any());
        }

        @Test
        @DisplayName("disabled account throws AuthException")
        void refresh_disabledAccount() {
            testUser.setEnabled(false);
            when(refreshTokenService.getUserFromToken("rawToken")).thenReturn(testUser);

            assertThatThrownBy(() -> authService.refresh("rawToken", request))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("disabled");
        }

        @Test
        @DisplayName("locked account (still locked) throws AuthException")
        void refresh_lockedAccount() {
            testUser.setAccountLocked(true);
            testUser.setLockedUntil(Instant.now().plusSeconds(600));
            when(refreshTokenService.getUserFromToken("rawToken")).thenReturn(testUser);

            assertThatThrownBy(() -> authService.refresh("rawToken", request))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("locked");
        }
    }

    @Nested
    @DisplayName("VerifyEmail")
    class VerifyEmailTests {

        @Test
        @DisplayName("valid token marks emailVerified=true and token used")
        void verifyEmail_success() {
            String rawToken = "rawVerifyToken";
            PasswordResetToken tokenEntity = PasswordResetToken.builder()
                    .token(dev.bermeb.authora.service.RefreshTokenService.hash(rawToken))
                    .user(testUser)
                    .tokenType(PasswordResetToken.TokenType.EMAIL_VERIFICATION)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .used(false)
                    .build();
            when(passwordResetTokenRepository.findByToken(anyString()))
                    .thenReturn(Optional.of(tokenEntity));
            when(userRepository.save(any())).thenReturn(testUser);
            when(passwordResetTokenRepository.save(any())).thenReturn(tokenEntity);

            authService.verifyEmail(rawToken);

            assertThat(testUser.isEmailVerified()).isTrue();
            assertThat(tokenEntity.isUsed()).isTrue();
            verify(userRepository).save(testUser);
        }

        @Test
        @DisplayName("invalid or expired token throws AuthException")
        void verifyEmail_invalidToken() {
            when(passwordResetTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.verifyEmail("badToken"))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("Invalid or expired");
        }

        @Test
        @DisplayName("used token (isValid=false) throws AuthException")
        void verifyEmail_usedToken() {
            String rawToken = "usedToken";
            PasswordResetToken usedTokenEntity = PasswordResetToken.builder()
                    .token(dev.bermeb.authora.service.RefreshTokenService.hash(rawToken))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .used(true)
                    .build();
            when(passwordResetTokenRepository.findByToken(anyString()))
                    .thenReturn(Optional.of(usedTokenEntity));

            assertThatThrownBy(() -> authService.verifyEmail(rawToken))
                    .isInstanceOf(AuthException.class);
        }
    }

    @Nested
    @DisplayName("ResetPassword")
    class ResetPasswordTests {

        @Test
        @DisplayName("valid token resets password, marks token used, revokes sessions")
        void resetPassword_success() {
            String rawToken = "rawResetToken";
            PasswordResetToken tokenEntity = PasswordResetToken.builder()
                    .token(dev.bermeb.authora.service.RefreshTokenService.hash(rawToken))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .used(false)
                    .build();
            when(passwordResetTokenRepository.findByToken(anyString()))
                    .thenReturn(Optional.of(tokenEntity));
            when(passwordEncoder.encode("NewPass1!")).thenReturn("$newHash");
            when(userRepository.save(any())).thenReturn(testUser);
            when(passwordResetTokenRepository.save(any())).thenReturn(tokenEntity);

            authService.resetPassword(rawToken, "NewPass1!");

            assertThat(testUser.getPasswordHash()).isEqualTo("$newHash");
            assertThat(tokenEntity.isUsed()).isTrue();
            verify(refreshTokenService).revokeAllForUser(testUser);
            verify(emailService).sendPasswordChangedNotice(testUser);
        }

        @Test
        @DisplayName("invalid token throws AuthException")
        void resetPassword_invalidToken() {
            when(passwordResetTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.resetPassword("bad", "NewPass1!"))
                    .isInstanceOf(AuthException.class);
        }
    }

    @Nested
    @DisplayName("ChangePassword")
    class ChangePasswordTests {

        @Test
        @DisplayName("success changes password, revokes all sessions, sends notice")
        void changePassword_success() {
            when(passwordEncoder.matches("currentPass", testUser.getPasswordHash())).thenReturn(true);
            when(passwordEncoder.encode("NewPass1!")).thenReturn("$encodedNew");
            when(userRepository.save(any())).thenReturn(testUser);

            authService.changePassword(testUser, "currentPass", "NewPass1!", request);

            assertThat(testUser.getPasswordHash()).isEqualTo("$encodedNew");
            verify(refreshTokenService).revokeAllForUser(testUser);
            verify(emailService).sendPasswordChangedNotice(testUser);
        }

        @Test
        @DisplayName("wrong current password throws AuthException")
        void changePassword_wrongCurrentPassword() {
            when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

            assertThatThrownBy(() ->
                    authService.changePassword(testUser, "wrongPass", "NewPass1!", request)
            ).isInstanceOf(AuthException.class)
                    .hasMessageContaining("Current password is incorrect");
        }
    }
}