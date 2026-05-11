package dev.bermeb.authora.service;

import dev.bermeb.authora.model.PasswordResetToken;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.PasswordResetTokenRepository;
import dev.bermeb.authora.util.TokenHashUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class EmailVerificationService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailService  emailService;

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Transactional
    public void issueFor(User user) {
        String rawToken = generateSecureToken();
        passwordResetTokenRepository.deleteByUserAndTokenType(
                user, PasswordResetToken.TokenType.EMAIL_VERIFICATION
        );
        PasswordResetToken token = PasswordResetToken.builder()
                .token(TokenHashUtil.hash(rawToken))
                .user(user)
                .tokenType(PasswordResetToken.TokenType.EMAIL_VERIFICATION)
                .expiresAt(Instant.now().plus(60, ChronoUnit.MINUTES))
                .createdAt(Instant.now())
                .build();
        passwordResetTokenRepository.save(token);
        emailService.sendEmailVerification(user, rawToken);
    }

    private static String generateSecureToken() {
        byte[] bytes = new byte[32];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}