package dev.bermeb.authora.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

@Data
@Validated
@ConfigurationProperties(prefix = "authora")
public class AuthoraProperties {

    @Valid
    private Jwt jwt = new Jwt();
    @Valid
    private RefreshToken refreshToken = new RefreshToken();
    @Valid
    private RateLimit rateLimit = new RateLimit();
    @Valid
    private PasswordPolicy passwordPolicy = new PasswordPolicy();
    @Valid
    private Email email = new Email();
    private Features features = new Features();
    @Valid
    private Cors cors = new Cors();

    @Data
    public static class Jwt {
        @NotBlank
        private String secret = "AUTHORA_JWT_SECRET";
        @Min(1)
        private long accessTokenExpirationMinutes = 15;
        private String issuer = "authora";
    }

    @Data
    public static class RefreshToken {
        @Min(1)
        private long expirationDays = 30;
        @Min(1)
        private int maxPerUser = 5;
        private boolean rotateOnUse = true;
    }

    @Data
    public static class RateLimit {
        private boolean enabled = true;
        @Min(1)
        private int loginAttemptsPerMinute = 10;
        @Min(1)
        private int maxFailedAttempts = 5;
        @Min(1)
        private int lockDurationMinutes = 15;

        @Valid
        private Map<String, PathLimit> paths = Map.of();

        @Data
        public static class PathLimit {
            @Min(1)
            private int capacity;
            @Min(1)
            private long periodSeconds;
        }
    }

    @Data
    public static class PasswordPolicy {
        @Min(12)
        private int minLength = 12;
        private boolean requireUppercase = true;
        private boolean requireLowercase = true;
        private boolean requireNumbers = true;
        private boolean requireSpecialCharacters = true;
        @Min(5)
        private int resetTokenExpiryMinutes = 30;
        @NotBlank
        private String pepper;
    }

    @Data
    public static class Email {
        private String fromAddress = "noreply@example.com";
        private String fromName = "Authora";
        private String applicationName = "Authora";
        @NotBlank
        private String baseUrl = "http://localhost:8080";
    }

    @Data
    public static class Features {
        private boolean oauth2Enabled = true;
        private boolean emailVerificationRequired = true;
        private boolean auditLogEnabled = true;
        private boolean twoFactorEnabled = false;
        private String oauth2RedirectUri = "http://localhost:3000/oauth2/callback";
    }

    @Data
    public static class Cors {
        private List<String> allowedOrigins = List.of("http://localhost:3000");
        private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
        private boolean allowedCredentials = true;
        private long maxAge = 3600;

        public boolean isAllowedOriginsSecure() {
            if (allowedOrigins == null) return true;
            return allowedOrigins.stream().allMatch(o ->
                    o.startsWith("https://")
                    || o.startsWith("http://localhost")
                    || o.startsWith("http://127.0.0.1")
            );
        }
    }
}