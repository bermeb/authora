package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.model.PasswordResetToken;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.PasswordResetTokenRepository;
import dev.bermeb.authora.repository.UserRepository;
import dev.bermeb.authora.security.UserPrincipal;
import dev.bermeb.authora.util.PasswordPolicyValidator;
import dev.bermeb.authora.util.TokenHashUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final AuthenticationManager authManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final EmailService emailService;
    private final AuditLogService auditLogService;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicyValidator passwordPolicyValidator;
    private final AuthoraProperties properties;
    private final CacheManager cacheManager;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public User register(String email, String password, String firstName, String lastName, HttpServletRequest request) {
        if (userRepository.existsByEmail(email.toLowerCase())) {
            throw new AuthException("Email already registered", HttpStatus.CONFLICT);
        }

        // Validate password strength in case the frontend didn't
        passwordPolicyValidator.validate(password);

        User user = User.builder()
                .email(email.toLowerCase())
                .passwordHash(passwordEncoder.encode(password)) // BCrypt hash
                .firstName(firstName)
                .lastName(lastName)
                // If verification is not required, we mark the email as verified
                .emailVerified(!properties.getFeatures().isEmailVerificationRequired())
                .roles(Set.of(Role.USER))
                .build();

        userRepository.save(user);
        auditLogService.logSuccess(AuditLog.AuditEventType.REGISTRATION, user, request);

        if (properties.getFeatures().isEmailVerificationRequired()) {
            String rawToken = generateSecureToken();
            passwordResetTokenRepository.deleteByUser(user);
            PasswordResetToken verifyToken = PasswordResetToken.builder()
                    .token(TokenHashUtil.hash(rawToken))
                    .user(user)
                    .tokenType(PasswordResetToken.TokenType.EMAIL_VERIFICATION)
                    .expiresAt(Instant.now().plus(60, ChronoUnit.MINUTES))
                    .createdAt(Instant.now())
                    .build();
            passwordResetTokenRepository.save(verifyToken);
            emailService.sendEmailVerification(user, rawToken);
        }
        return user;
    }

    @Transactional
    public Map<String, Object> login(String email, String password, HttpServletRequest request) {
        User user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> {
                    // Log failure even for unknown emails; return generic message
                    auditLogService.logFailure(AuditLog.AuditEventType.LOGIN_FAILURE, email, "User not found", request);
                    return new AuthException("Invalid credentials");
                });

        checkAccountStatus(user);

        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(email.toLowerCase(), password)
            );

            user.resetFailedLoginAttempts();
            userRepository.updateLastLoginAt(user.getId(), Instant.now());
            userRepository.save(user);


            String accessToken = jwtService.generateAccessToken((UserDetails) Objects.requireNonNull(auth.getPrincipal()));
            String refreshToken = refreshTokenService.createRefreshToken(user, request);

            auditLogService.logSuccess(AuditLog.AuditEventType.LOGIN_SUCCESS, user, request);

            return Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken,
                    "expiresIn", jwtService.getAccessTokenExpirationSeconds(),
                    "user", user
            );
        } catch (BadCredentialsException e) {
            handleFailedLogin(user, request);
            throw new AuthException("Invalid credentials");
        } catch (LockedException e) {
            throw new AuthException("Account is currently locked. Try again later");
        } catch (DisabledException e) {
            throw new AuthException("Account is disabled");
        }
    }

    @Transactional(noRollbackFor = AuthException.class)
    public Map<String, Object> refresh(String rawRefreshToken, HttpServletRequest request) {
        User user = refreshTokenService.getUserFromToken(rawRefreshToken);

        checkAccountStatus(user);

        String newRefreshToken = properties.getRefreshToken().isRotateOnUse()
                ? refreshTokenService.rotateRefreshToken(rawRefreshToken, request)
                : rawRefreshToken;

        UserPrincipal principal = UserPrincipal.of(user);
        String accessToken = jwtService.generateAccessToken(principal);

        auditLogService.logSuccess(AuditLog.AuditEventType.TOKEN_REFRESHED, user, request);

        return Map.of(
                "accessToken", accessToken,
                "refreshToken", newRefreshToken,
                "expiresIn", jwtService.getAccessTokenExpirationSeconds()
        );
    }

    @Transactional
    public void logout(String rawRefreshToken, User user, HttpServletRequest request) {
        refreshTokenService.revokeToken(rawRefreshToken);
        auditLogService.logSuccess(AuditLog.AuditEventType.LOGOUT, user, request);
    }

    @Transactional
    public void logoutAll(User user, HttpServletRequest request) {
        refreshTokenService.revokeAllForUser(user);
        auditLogService.logSuccess(AuditLog.AuditEventType.LOGOUT, user, "All sessions revoked", request);
    }

    @Transactional
    public void verifyEmail(String rawToken) {
        String hash = TokenHashUtil.hash(rawToken);
        PasswordResetToken token = passwordResetTokenRepository.findByToken(hash)
                .filter(t -> t.isValid() && t.getTokenType() == PasswordResetToken.TokenType.EMAIL_VERIFICATION)
                .orElseThrow(() -> new AuthException("Invalid or expired verification link"));

        User user = token.getUser();
        user.setEmailVerified(true);
        userRepository.save(user);

        token.setUsed(true);
        passwordResetTokenRepository.save(token);

        auditLogService.logSuccess(AuditLog.AuditEventType.EMAIL_VERIFICATION, user, null, null);
    }

    @Transactional
    public void requestPasswordReset(String email, HttpServletRequest request) {
        userRepository.findByEmail(email.toLowerCase()).ifPresent(user -> {
            if (!user.isLocalUser()) return; // OAuth2 users don't have password

            String rawToken = generateSecureToken();
            // Invalidate any existing reset tokens before creating a new one
            passwordResetTokenRepository.deleteByUser(user);
            PasswordResetToken token = PasswordResetToken.builder()
                    .token(TokenHashUtil.hash(rawToken))
                    .user(user)
                    .tokenType(PasswordResetToken.TokenType.PASSWORD_RESET)
                    .expiresAt(Instant.now().plus(
                            properties.getPasswordPolicy().getResetTokenExpiryMinutes(), ChronoUnit.MINUTES
                    ))
                    .createdAt(Instant.now())
                    .build();

            passwordResetTokenRepository.save(token);
            emailService.sendPasswordReset(user, rawToken);
            auditLogService.logSuccess(AuditLog.AuditEventType.PASSWORD_RESET_REQUESTED, user, request);
        });
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        String hash = TokenHashUtil.hash(rawToken);
        PasswordResetToken token = passwordResetTokenRepository.findByToken(hash)
                .filter(t -> t.isValid() && t.getTokenType() == PasswordResetToken.TokenType.PASSWORD_RESET)
                .orElseThrow(() -> new AuthException("Invalid or expired reset token"));

        passwordPolicyValidator.validate(newPassword);

        User user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.resetFailedLoginAttempts();
        userRepository.save(user);

        // Mark the token as used
        token.setUsed(true);
        passwordResetTokenRepository.save(token);

        // Revoke all session
        refreshTokenService.revokeAllForUser(user);
        emailService.sendPasswordChangedNotice(user);
        auditLogService.logSuccess(AuditLog.AuditEventType.PASSWORD_RESET_COMPLETED, user, null, null);
    }

    @Transactional
    public void changePassword(User user, String currentPassword, String newPassword, HttpServletRequest request) {
        // OAuth2 users have no password hash - reject immediately with a clear 401
        if (!user.isLocalUser()) {
            throw new AuthException("Password change is not available for accounts signed in with a social provider");
        }

        // Verify current password to prevent stolen sessions from locking out the owner
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new AuthException("Current password is incorrect");
        }

        passwordPolicyValidator.validate(newPassword);

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Revoke all session
        refreshTokenService.revokeAllForUser(user);
        emailService.sendPasswordChangedNotice(user);
        auditLogService.logSuccess(AuditLog.AuditEventType.PASSWORD_CHANGED, user, request);
    }

    public Map<String, Object> exchangeOAuth2Code(String code) {
        Cache cache = cacheManager.getCache("oauth2PendingTokens");
        if (cache == null) {
            throw new AuthException("OAuth2 exchange not available");
        }

        Cache.ValueWrapper valueWrapper = cache.get(code);
        if (valueWrapper == null) {
            throw new AuthException("Invalid or expired authorization code");
        }

        // Delete the code after retrieval
        cache.evict(code);

        @SuppressWarnings("unchecked") // safe cast: we know we stored Map<String, Object>
        Map<String, Object> tokens = (Map<String, Object>) valueWrapper.get();
        return tokens;
    }

    private void checkAccountStatus(User user) {
        if (!user.isEnabled()) {
            throw new AuthException("Account is disabled");
        }

        if (user.isAccountLocked()) {
            if (user.getLockedUntil() != null && Instant.now().isAfter(user.getLockedUntil())) {
                // Lock has expired - clearing it
                user.resetFailedLoginAttempts();
                userRepository.save(user);
            } else {
                throw new AuthException("Account is currently locked. Try again later");
            }
        }

        if (properties.getFeatures().isEmailVerificationRequired() && !user.isEmailVerified()) {
            throw new AuthException("Please verify your email address before logging in", HttpStatus.FORBIDDEN);
        }
    }

    private void handleFailedLogin(User user, HttpServletRequest request) {
        user.incrementFailedLoginAttempts();
        int maxAttempts = properties.getRateLimit().getMaxFailedAttempts();

        if (user.getFailedLoginAttempts() >= maxAttempts) {
            user.setAccountLocked(true);
            user.setLockedUntil(Instant.now().plus(
                    properties.getRateLimit().getLockDurationMinutes(), ChronoUnit.MINUTES
            ));
            auditLogService.logFailure(AuditLog.AuditEventType.ACCOUNT_LOCKED, user,
                    "Locked after + " + user.getFailedLoginAttempts() + " failed attempts", request);
        } else {
            auditLogService.logFailure(AuditLog.AuditEventType.LOGIN_FAILURE, user,
                    "Attempt " + user.getFailedLoginAttempts() + "/" + maxAttempts, request);
        }
        userRepository.save(user);
    }

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }
}