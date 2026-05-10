package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import dev.bermeb.authora.model.RefreshToken;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.RefreshTokenRepository;
import dev.bermeb.authora.util.TokenHashUtil;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

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
        String h1 = TokenHashUtil.hash("someToken");
        String h2 = TokenHashUtil.hash("someToken");
        assertThat(h1).isEqualTo(h2).hasSize(64);
    }

    @Test
    @DisplayName("hash() produces different output for different inputs")
    void hash_differentForDifferentInputs() {
        assertThat(TokenHashUtil.hash("a")).isNotEqualTo(TokenHashUtil.hash("b"));
    }

    @Nested
    @DisplayName("createRefreshToken")
    class CreateRefreshToken {

        @Test
        @DisplayName("saves hashed token and returns raw token")
        void create_savesAndReturnsRaw() {
            when(refreshTokenRepository.findByUserAndRevokedFalseOrderByCreatedAtAsc(any()))
                    .thenReturn(new java.util.ArrayList<>());
            when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            String raw = refreshTokenService.createRefreshToken(testUser, request);

            assertThat(raw).isNotBlank();
            ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
            verify(refreshTokenRepository).save(captor.capture());
            assertThat(captor.getValue().getToken()).isEqualTo(TokenHashUtil.hash(raw));
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
            RefreshToken mid = RefreshToken.builder()
                    .token("midhash")
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(100))
                    .createdAt(Instant.now().minusSeconds(100))
                    .build();
            RefreshToken newest = RefreshToken.builder()
                    .token("newhash")
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(100))
                    .createdAt(Instant.now())
                    .build();
            // Return a mutable list with 3 tokens (= max per user), so the oldest gets evicted
            when(refreshTokenRepository.findByUserAndRevokedFalseOrderByCreatedAtAsc(any()))
                    .thenReturn(new ArrayList<>(List.of(oldest, mid, newest)));
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
            UUID existingId = UUID.randomUUID();
            RefreshToken existing = RefreshToken.builder()
                    .id(existingId)
                    .token(TokenHashUtil.hash(rawOld))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(existing));
            when(refreshTokenRepository.markRevoked(eq(existingId), any(Instant.class), eq("ROTATED")))
                    .thenReturn(1);
            when(refreshTokenRepository.findByUserAndRevokedFalseOrderByCreatedAtAsc(any()))
                    .thenReturn(new ArrayList<>());
            when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));

            String newToken = refreshTokenService.rotateRefreshToken(rawOld, request);

            assertThat(newToken).isNotBlank().isNotEqualTo(rawOld);
            verify(refreshTokenRepository).markRevoked(eq(existingId), any(Instant.class), eq("ROTATED"));
        }

        @Test
        @DisplayName("detects token reuse, revokes all user tokens, throws")
        void rotate_reuseDetected() {
            String reusedRaw = "reusedRaw";
            RefreshToken revoked = RefreshToken.builder()
                    .token(TokenHashUtil.hash(reusedRaw))
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
                    .token(TokenHashUtil.hash(raw))
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
                    .token(TokenHashUtil.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(active));

            User result = refreshTokenService.getUserFromToken(raw, request);

            assertThat(result).isEqualTo(testUser);
        }

        @Test
        @DisplayName("returns user for expired token (activity check is caller's job)")
        void getUser_expiredStillReturnsUser() {
            String raw = "expiredToken";
            RefreshToken expired = RefreshToken.builder()
                    .token(TokenHashUtil.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now().minusSeconds(100))
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(expired));

            assertThat(refreshTokenService.getUserFromToken(raw, request)).isEqualTo(testUser);
        }

        @Test
        @DisplayName("returns user for revoked token so rotateRefreshToken can run reuse detection")
        void getUser_revokedStillReturnsUser() {
            String raw = "revokedToken";
            RefreshToken revoked = RefreshToken.builder()
                    .token(TokenHashUtil.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(true)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(revoked));

            assertThat(refreshTokenService.getUserFromToken(raw, request)).isEqualTo(testUser);
        }

        @Test
        @DisplayName("throws when no record exists for the token")
        void getUser_unknownToken() {
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> refreshTokenService.getUserFromToken("nope", request))
                    .isInstanceOf(AuthException.class);
        }
    }

    @Nested
    @DisplayName("validateActive")
    class ValidateActive {

        @Test
        @DisplayName("passes for active token")
        void validate_active() {
            String raw = "activeToken";
            RefreshToken active = RefreshToken.builder()
                    .token(TokenHashUtil.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(active));

            refreshTokenService.validateActive(raw, request);
        }

        @Test
        @DisplayName("throws for expired token")
        void validate_expired() {
            String raw = "expiredToken";
            RefreshToken expired = RefreshToken.builder()
                    .token(TokenHashUtil.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().minusSeconds(1))
                    .createdAt(Instant.now().minusSeconds(100))
                    .revoked(false)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(expired));

            assertThatThrownBy(() -> refreshTokenService.validateActive(raw, request))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("expired or revoked");
        }

        @Test
        @DisplayName("throws for revoked token")
        void validate_revoked() {
            String raw = "revokedToken";
            RefreshToken revoked = RefreshToken.builder()
                    .token(TokenHashUtil.hash(raw))
                    .user(testUser)
                    .expiresAt(Instant.now().plusSeconds(3600))
                    .createdAt(Instant.now())
                    .revoked(true)
                    .build();
            when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(revoked));

            assertThatThrownBy(() -> refreshTokenService.validateActive(raw, request))
                    .isInstanceOf(AuthException.class)
                    .hasMessageContaining("expired or revoked");
        }
    }

    @Test
    @DisplayName("revokeToken marks token revoked with USER_LOGOUT reason")
    void revokeToken_success() {
        String raw = "tokenToRevoke";
        RefreshToken rt = RefreshToken.builder()
                .token(TokenHashUtil.hash(raw))
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