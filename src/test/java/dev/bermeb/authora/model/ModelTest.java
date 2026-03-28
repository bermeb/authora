package dev.bermeb.authora.model;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class ModelTest {

    @Nested
    @DisplayName("User")
    class UserTests {

        private User buildUser(String firstName, String lastName, String oauthProvider) {
            return User.builder()
                    .id(UUID.randomUUID())
                    .email("u@example.com")
                    .firstName(firstName)
                    .lastName(lastName)
                    .oauthProvider(oauthProvider)
                    .roles(Set.of(Role.USER))
                    .build();
        }

        @Test
        @DisplayName("getFullName() concatenates firstName and lastName with a space")
        void getFullName() {
            assertThat(buildUser("Jane", "Doe", null).getFullName()).isEqualTo("Jane Doe");
        }

        @Test
        @DisplayName("isLocalUser() is true when oauthProvider is null")
        void isLocalUser_null() {
            assertThat(buildUser("A", "B", null).isLocalUser()).isTrue();
        }

        @Test
        @DisplayName("isLocalUser() is false when oauthProvider is set")
        void isLocalUser_withProvider() {
            assertThat(buildUser("A", "B", "google").isLocalUser()).isFalse();
        }

        @Test
        @DisplayName("incrementFailedLoginAttempts() increments the counter")
        void incrementFailedLoginAttempts() {
            User user = buildUser("A", "B", null);
            user.incrementFailedLoginAttempts();
            user.incrementFailedLoginAttempts();
            assertThat(user.getFailedLoginAttempts()).isEqualTo(2);
        }

        @Test
        @DisplayName("resetFailedLoginAttempts() zeroes counter and clears lock state")
        void resetFailedLoginAttempts() {
            User user = buildUser("A", "B", null);
            user.setFailedLoginAttempts(5);
            user.setAccountLocked(true);
            user.setLockedUntil(Instant.now().plusSeconds(300));

            user.resetFailedLoginAttempts();

            assertThat(user.getFailedLoginAttempts()).isZero();
            assertThat(user.isAccountLocked()).isFalse();
            assertThat(user.getLockedUntil()).isNull();
        }
    }

    @Nested
    @DisplayName("RefreshToken")
    class RefreshTokenTests {

        @Test
        @DisplayName("isExpired() returns true when expiresAt is in the past")
        void isExpired_past() {
            RefreshToken rt = RefreshToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now())
                    .build();
            Assertions.assertThat(rt.isExpired()).isTrue();
        }

        @Test
        @DisplayName("isExpired() returns false when expiresAt is in the future")
        void isExpired_future() {
            RefreshToken rt = RefreshToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .build();
            Assertions.assertThat(rt.isExpired()).isFalse();
        }

        @Test
        @DisplayName("isActive() is false when revoked")
        void isActive_revoked() {
            RefreshToken rt = RefreshToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(true)
                    .build();
            Assertions.assertThat(rt.isActive()).isFalse();
        }

        @Test
        @DisplayName("isActive() is false when expired")
        void isActive_expired() {
            RefreshToken rt = RefreshToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            Assertions.assertThat(rt.isActive()).isFalse();
        }

        @Test
        @DisplayName("isActive() is true when not revoked and not expired")
        void isActive_active() {
            RefreshToken rt = RefreshToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            Assertions.assertThat(rt.isActive()).isTrue();
        }

        @Test
        @DisplayName("revoke(reason) sets revoked=true, revokedAt, and revokedReason")
        void revoke_setsFields() {
            RefreshToken rt = RefreshToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .build();

            rt.revoke("USER_LOGOUT");

            Assertions.assertThat(rt.isRevoked()).isTrue();
            Assertions.assertThat(rt.getRevokedAt()).isNotNull();
            Assertions.assertThat(rt.getRevokedReason()).isEqualTo("USER_LOGOUT");
        }
    }

    @Nested
    @DisplayName("PasswordResetToken")
    class PasswordResetTokenTests {

        @Test
        @DisplayName("isExpired() returns true when past expiry")
        void isExpired_past() {
            PasswordResetToken t = PasswordResetToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now())
                    .build();
            Assertions.assertThat(t.isExpired()).isTrue();
        }

        @Test
        @DisplayName("isExpired() returns false when before expiry")
        void isExpired_future() {
            PasswordResetToken t = PasswordResetToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .build();
            Assertions.assertThat(t.isExpired()).isFalse();
        }

        @Test
        @DisplayName("isValid() returns false when expired")
        void isValid_expired() {
            PasswordResetToken t = PasswordResetToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now())
                    .used(false)
                    .build();
            Assertions.assertThat(t.isValid()).isFalse();
        }

        @Test
        @DisplayName("isValid() returns false when already used")
        void isValid_used() {
            PasswordResetToken t = PasswordResetToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .used(true)
                    .build();
            Assertions.assertThat(t.isValid()).isFalse();
        }

        @Test
        @DisplayName("isValid() returns true when not used and not expired")
        void isValid_valid() {
            PasswordResetToken t = PasswordResetToken.builder()
                    .token("hash")
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .used(false)
                    .build();
            Assertions.assertThat(t.isValid()).isTrue();
        }
    }
}