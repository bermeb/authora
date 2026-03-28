package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import dev.bermeb.authora.model.RefreshToken;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RefreshTokenServiceTest {

    @Mock
    RefreshTokenRepository refreshTokenRepository;
    @Mock
    AuthoraProperties properties;
    @Mock
    AuditLogService auditLogService;
    @Mock
    HttpServletRequest request;

    @InjectMocks
    RefreshTokenService refreshTokenService;

    private User testUser;

    @BeforeEach
    void setup() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .email("test@example.com")
                .build();

        AuthoraProperties.RefreshToken rtProps = new AuthoraProperties.RefreshToken();
        rtProps.setExpirationDays(7);
        rtProps.setMaxPerUser(3);
        when(properties.getRefreshToken()).thenReturn(rtProps);
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getHeader("User-Agent")).thenReturn("JUnit");
    }

    @Test
    @DisplayName("hash() is deterministic for the same input")
    void hash_isDeterministic() {
        String h1 = RefreshTokenService.hash("someToken");
        String h2 = RefreshTokenService.hash("someToken");
        assertThat(h1).isEqualTo(h2).hasSize(64);
    }

    @Test
    @DisplayName("hash() produces different output for different inputs")
    void hash_differentForDifferentInputs() {
        assertThat(RefreshTokenService.hash("a")).isNotEqualTo(RefreshTokenService.hash("b"));
    }

    @Nested
    @DisplayName("createRefreshToken")
    class CreateRefreshToken {

        @Test
        @DisplayName("saves hashed token and returns raw token")
        void create_savesAndReturnsRaw() {
            when(refreshTokenRepository.countByUserAndRevokedFalse(any())).thenReturn(0L);
            when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            String raw = refreshTokenService.createRefreshToken(testUser, request);

            assertThat(raw).isNotBlank();
            ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
            verify(refreshTokenRepository).save(captor.capture());
            assertThat(captor.getValue().getToken()).isEqualTo(RefreshTokenService.hash(raw));
            assertThat(captor.getValue().getUser()).isEqualTo(testUser);
        }

        @Test
        @DisplayName("revokes oldest token when at max limit")
        void create_enforcesMaxLimit() {
            when(refreshTokenRepository.countByUserAndRevokedFalse(any())).thenReturn(3L);
            RefreshToken oldest = RefreshToken.builder()
                    .token("oldhash")
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(100))
                    .createdAt(Instant.now().minusSeconds(200))
                    .build();
            when(refreshTokenRepository.findByUserAndRevokedFalseOrderByCreatedAtAsc(any()))
                    .thenReturn(List.of(oldest));
            when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            refreshTokenService.createRefreshToken(testUser, request);

            assertThat(oldest.isRevoked()).isTrue();
            assertThat(oldest.getRevokedReason()).isEqualTo("MAX_TOKENS_REACHED");
        }
    }

    @Nested
    @DisplayName("rotateRefreshToken")
    class RotateRefreshToken {

        @Test
        @DisplayName("revokes old token and returns new raw token")
        void rotate_success() {
            String rawOld = "oldRawToken";
            RefreshToken existing = RefreshToken.builder()
                    .token(RefreshTokenService.hash(rawOld))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(existing));
            when(refreshTokenRepository.countByUserAndRevokedFalse(any())).thenReturn(0L);
            when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            String newToken = refreshTokenService.rotateRefreshToken(rawOld, request);

            assertThat(newToken).isNotBlank().isNotEqualTo(rawOld);
            assertThat(existing.isRevoked()).isTrue();
            assertThat(existing.getRevokedReason()).isEqualTo("ROTATED");
        }

        @Test
        @DisplayName("detects token reuse, revokes all user tokens, throws")
        void rotate_reuseDetected() {
            String reusedRaw = "reusedRaw";
            RefreshToken revoked = RefreshToken.builder()
                    .token(RefreshTokenService.hash(reusedRaw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(100))
                    .createdAt(Instant.now())
                    .revoked(true)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(revoked));

            assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken(reusedRaw, request))
                    .isInstanceOf(AuthException.class);

            verify(refreshTokenRepository).revokeAllForUser(eq(testUser), any(Instant.class), eq("TOKEN_REUSE_DETECTED"));
            verify(auditLogService).logSuspiciousActivity(eq(testUser), anyString(), eq(request));
        }

        @Test
        @DisplayName("expired (not revoked) token throws without reuse alarm")
        void rotate_expiredNotRevoked() {
            String raw = "expiredRaw";
            RefreshToken expired = RefreshToken.builder()
                    .token(RefreshTokenService.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().minusSeconds(10))
                    .createdAt(Instant.now().minusSeconds(100))
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(expired));

            assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken(raw, request))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("expired");

            verify(refreshTokenRepository, never()).revokeAllForUser(any(), any(), any());
        }

        @Test
        @DisplayName("throws AuthException for unknown token")
        void rotate_notFound() {
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("unknown", request))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("Invalid refresh token");
        }
    }

    @Nested
    @DisplayName("getUserFromToken")
    class GetUserFromToken {

        @Test
        @DisplayName("returns user for active token")
        void getUser_active() {
            String raw = "activeToken";
            RefreshToken active = RefreshToken.builder()
                    .token(RefreshTokenService.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(active));

            User result = refreshTokenService.getUserFromToken(raw);

            assertThat(result).isEqualTo(testUser);
        }

        @Test
        @DisplayName("throws for expired token")
        void getUser_expired() {
            String raw = "expiredToken";
            RefreshToken expired = RefreshToken.builder()
                    .token(RefreshTokenService.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now().minusSeconds(100))
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(expired));

            assertThatThrownBy(() -> refreshTokenService.getUserFromToken(raw))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("Invalid or expired");
        }

        @Test
        @DisplayName("throws for revoked token")
        void getUser_revoked() {
            String raw = "revokedToken";
            RefreshToken revoked = RefreshToken.builder()
                    .token(RefreshTokenService.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(true)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(revoked));

            assertThatThrownBy(() -> refreshTokenService.getUserFromToken(raw))
                    .isInstanceOf(AuthException.class);
        }
    }

    @Test
    @DisplayName("revokeToken marks token revoked with USER_LOGOUT reason")
    void revokeToken_success() {
        String raw = "tokenToRevoke";
        RefreshToken rt = RefreshToken.builder()
                .token(RefreshTokenService.hash(raw))
                .user(testUser)
                .expiresAt(Instant.now().plusSeconds(3600))
                .createdAt(Instant.now())
                .revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(rt));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

        refreshTokenService.revokeToken(raw);

        assertThat(rt.isRevoked()).isTrue();
        assertThat(rt.getRevokedReason()).isEqualTo("USER_LOGOUT");
        verify(refreshTokenRepository).save(rt);
    }

    @Test
    @DisplayName("revokeToken silently ignores unknown token")
    void revokeToken_unknownToken() {
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        assertThatCode(() -> refreshTokenService.revokeToken("unknown"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("revokeAllForUser delegates to repository with correct reason")
    void revokeAllForUser_delegates() {
        refreshTokenService.revokeAllForUser(testUser);

        verify(refreshTokenRepository).revokeAllForUser(
                eq(testUser), any(Instant.class), eq("ALL_SESSIONS_REVOKED"));
    }

    @Test
    @DisplayName("cleanupExpiredTokens calls deleteExpiredAndRevoked")
    void cleanup_callsRepo() {
        refreshTokenService.cleanupExpiredTokens();

        verify(refreshTokenRepository).deleteExpiredAndRevoked(any(Instant.class));
    }
}