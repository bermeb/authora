package dev.bermeb.authora.security;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.service.AuditLogService;
import dev.bermeb.authora.service.JwtService;
import dev.bermeb.authora.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationSuccessHandlerTest {

    @Mock
    JwtService jwtService;
    @Mock
    RefreshTokenService refreshTokenService;
    @Mock
    AuditLogService auditLogService;
    @Mock
    AuthoraProperties properties;
    @Mock
    CacheManager cacheManager;
    @Mock
    Cache pendingTokenCache;

    OAuth2AuthenticationSuccessHandler handler;

    private User user;
    private OAuth2UserPrincipal principal;

    @BeforeEach
    void setUp() {
        handler = new OAuth2AuthenticationSuccessHandler(
                jwtService, refreshTokenService, auditLogService, properties, cacheManager);

        user = User.builder()
                .id(UUID.randomUUID())
                .email("oauth@example.com")
                .firstName("OAuth")
                .lastName("User")
                .roles(Set.of(Role.USER))
                .build();

        principal = OAuth2UserPrincipal.of(user, Map.of("sub", "g-123"));

        AuthoraProperties.Features features = new AuthoraProperties.Features();
        features.setOauth2RedirectUri("https://app.example.com/oauth2/callback");
        when(properties.getFeatures()).thenReturn(features);

        when(cacheManager.getCache("oauth2PendingTokens")).thenReturn(pendingTokenCache);
        when(jwtService.generateAccessToken(any())).thenReturn("access-token-value");
        when(refreshTokenService.createRefreshToken(any(), any())).thenReturn("refresh-token-value");
        when(jwtService.getAccessTokenExpirationSeconds()).thenReturn(900L);
    }

    @Test
    @DisplayName("onAuthenticationSuccess stores tokens in cache and redirects with code param")
    void onAuthenticationSuccess_redirectsWithCode() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        handler.onAuthenticationSuccess(request, response, auth);

        String redirectUrl = response.getRedirectedUrl();
        assertThat(redirectUrl).isNotNull();
        assertThat(redirectUrl).startsWith("https://app.example.com/oauth2/callback");
        assertThat(redirectUrl).contains("code=");
    }

    @Test
    @DisplayName("onAuthenticationSuccess puts access and refresh tokens into pending token cache")
    void onAuthenticationSuccess_putsTokensInCache() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        handler.onAuthenticationSuccess(request, response, auth);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(pendingTokenCache).put(anyString(), captor.capture());

        Map<String, Object> tokenMap = captor.getValue();
        assertThat(tokenMap).containsKey("accessToken");
        assertThat(tokenMap).containsKey("refreshToken");
        assertThat(tokenMap).containsKey("expiresIn");
        assertThat(tokenMap.get("accessToken")).isEqualTo("access-token-value");
        assertThat(tokenMap.get("refreshToken")).isEqualTo("refresh-token-value");
    }

    @Test
    @DisplayName("onAuthenticationSuccess generates JWT and refresh token for the OAuth2 user")
    void onAuthenticationSuccess_generatesTokens() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        handler.onAuthenticationSuccess(request, response, auth);

        verify(jwtService).generateAccessToken(any(UserPrincipal.class));
        verify(refreshTokenService).createRefreshToken(eq(user), any());
    }

    @Test
    @DisplayName("onAuthenticationSuccess logs OAUTH2_LOGIN audit event")
    void onAuthenticationSuccess_logsAudit() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());

        handler.onAuthenticationSuccess(request, response, auth);

        verify(auditLogService).logSuccess(any(), eq(user), any());
    }
}