package dev.bermeb.authora.security;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.service.AuditLogService;
import dev.bermeb.authora.service.JwtService;
import dev.bermeb.authora.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.cache.CacheManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogService auditLogService;
    private final AuthoraProperties properties;
    private final CacheManager cacheManager;

    private final static SecureRandom SECURE_RANDOM = new SecureRandom();

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request,
                                        @NonNull HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) authentication.getPrincipal();

        if (principal == null) {
            throw new RuntimeException("Principal is null");
        }

        String accessToken = jwtService.generateAccessToken(UserPrincipal.of(principal.getUser()));
        String refreshToken = refreshTokenService.createRefreshToken(principal.getUser(), request);

        auditLogService.logSuccess(AuditLog.AuditEventType.OAUTH2_LOGIN, principal.getUser(), request);

        byte[] bytes = new byte[16];
        SECURE_RANDOM.nextBytes(bytes);
        String code = Base64.getEncoder().withoutPadding().encodeToString(bytes);

        Objects.requireNonNull(cacheManager.getCache("oauth2PendingTokens")).put(accessToken, Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "expiresIn", jwtService.getAccessTokenExpirationSeconds()
        ));

        String redirectUrl = UriComponentsBuilder
                .fromUriString(properties.getFeatures().getOauth2RedirectUri())
                .queryParam("code", code)
                .build().toString();

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}