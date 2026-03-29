package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import dev.bermeb.authora.model.RefreshToken;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AuthoraProperties properties;
    private final AuditLogService auditLogService;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public String createRefreshToken(User user, HttpServletRequest request) {
        enforceMaxTokenLimit(user);

        String rawToken = generateSecureToken();
        String tokenHash = hash(rawToken);

        RefreshToken rt = RefreshToken.builder()
                .token(tokenHash)
                .user(user)
                .expiresAt(Instant.now().plus(properties.getRefreshToken().getExpirationDays(), ChronoUnit.DAYS))
                .createdAt(Instant.now())
                .createdByIp(request.getRemoteAddr())
                .userAgent(request.getHeader("User-Agent"))
                .build();

        refreshTokenRepository.save(rt);
        return rawToken;
    }

    @Transactional
    public String rotateRefreshToken(String rawToken, HttpServletRequest request) {
        String hash = hash(rawToken);
        RefreshToken existing = refreshTokenRepository.findByToken(hash)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (!existing.isActive()) {
            if(existing.isRevoked()) {
                log.warn("Refresh token reuse detected for user {}", existing.getUser().getEmail());
                refreshTokenRepository.revokeAllForUser(
                        existing.getUser(), Instant.now(), "TOKEN_REUSE_DETECTED"
                );
                auditLogService.logSuspiciousActivity(existing.getUser(),
                        "Refresh token reuse detected", request
                );
            }
            throw new AuthException("Refresh token expired or revoked");
        }

        existing.revoke("ROTATED");
        refreshTokenRepository.save(existing);

        return createRefreshToken(existing.getUser(), request);
    }

    @Transactional(readOnly = true)
    public User getUserFromToken(String rawToken) {
        return refreshTokenRepository.findByToken(hash(rawToken))
                .filter(RefreshToken::isActive)
                .map(RefreshToken::getUser)
                .orElseThrow(() -> new AuthException("Invalid or expired refresh token"));
    }

    @Transactional
    public void revokeToken(String rawToken) {
        refreshTokenRepository.findByToken(hash(rawToken)).ifPresent(rt -> {
           rt.revoke("USER_LOGOUT");
           refreshTokenRepository.save(rt);
        });
    }

    @Transactional
    public void revokeAllForUser(User user) {
        refreshTokenRepository.revokeAllForUser(user, Instant.now(), "ALL_SESSIONS_REVOKED");
    }

    @Scheduled(cron = "0 0 3 * * *") // every day at 03:00
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired/revoked refresh tokens…");
        // Keep tokens for 1 extra day after expiry (1-day grace window for investigation)
        refreshTokenRepository.deleteExpiredAndRevoked(Instant.now().minus(1, ChronoUnit.DAYS));
    }

    private void enforceMaxTokenLimit(User user) {
        List<RefreshToken> activeTokens = refreshTokenRepository
                .findByUserAndRevokedFalseOrderByCreatedAtAsc(user);
        int max = properties.getRefreshToken().getMaxPerUser();

        while (activeTokens.size() >= max) {
            RefreshToken oldest = activeTokens.removeFirst();
            oldest.revoke("MAX_TOKENS_REACHED");
            refreshTokenRepository.save(oldest);
        }
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[48];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String hash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            // Hexformat.of().formatHex() converts byte array to lowercase hex string
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}