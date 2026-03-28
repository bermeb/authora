package dev.bermeb.authora.security;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class PepperedPasswordEncoder implements PasswordEncoder {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final BCryptPasswordEncoder bcrypt;
    private final SecretKeySpec pepperKey;

    public PepperedPasswordEncoder(int bcryptStrength, String pepper) {
        if (pepper == null || pepper.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException(
                    "Pepper must be at least 32 bytes for HMAC-SHA256 security."
            );
        }
        this.bcrypt = new BCryptPasswordEncoder(bcryptStrength);
        this.pepperKey = new SecretKeySpec(
                pepper.getBytes(StandardCharsets.UTF_8),
                HMAC_ALGORITHM
        );
    }

    @Override
    public String encode(CharSequence rawPassword) { return bcrypt.encode(hmac(rawPassword)); }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return bcrypt.matches(hmac(rawPassword), encodedPassword);
    }

    private String hmac(CharSequence rawPassword) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(pepperKey);
            byte[] hmacBytes = mac.doFinal(
                    rawPassword.toString().getBytes(StandardCharsets.UTF_8)
            );
            return Base64.getEncoder().encodeToString(hmacBytes);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA256 computation failed", e);
        }
    }
}