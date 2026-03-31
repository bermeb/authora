package dev.bermeb.authora.security;

import dev.bermeb.authora.config.AuthoraProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuth2AuthenticationFailureHandlerTest {

    @Mock
    AuthoraProperties properties;

    @InjectMocks
    OAuth2AuthenticationFailureHandler handler;

    private AuthoraProperties.Features features;

    @BeforeEach
    void setUp() {
        features = new AuthoraProperties.Features();
        features.setOauth2RedirectUri("https://app.example.com/oauth2/callback");
        when(properties.getFeatures()).thenReturn(features);
    }

    @Test
    @DisplayName("onAuthenticationFailure redirects to origin /oauth2/error with encoded message")
    void onAuthenticationFailure_redirectsToErrorUrl() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        BadCredentialsException ex = new BadCredentialsException("Bad credentials");

        handler.onAuthenticationFailure(request, response, ex);

        String redirectUrl = response.getRedirectedUrl();
        assertThat(redirectUrl).isNotNull();
        assertThat(redirectUrl).startsWith("https://app.example.com/oauth2/error");
        assertThat(redirectUrl).contains("message=");
    }

    @Test
    @DisplayName("onAuthenticationFailure uses the origin from the configured redirect URI")
    void onAuthenticationFailure_usesCorrectOrigin() throws Exception {
        features.setOauth2RedirectUri("https://frontend.myapp.io/callback");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("err"));

        assertThat(response.getRedirectedUrl()).startsWith("https://frontend.myapp.io/oauth2/error");
    }
}