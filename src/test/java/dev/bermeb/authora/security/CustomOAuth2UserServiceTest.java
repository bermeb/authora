package dev.bermeb.authora.security;

import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestOperations;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class CustomOAuth2UserServiceTest {

    @Mock
    UserRepository userRepository;

    @Mock
    RestOperations restOperations;

    CustomOAuth2UserService service;

    @BeforeEach
    void setUp() {
        service = new CustomOAuth2UserService(userRepository);
        // Inject mock RestOperations to avoid real HTTP calls to OAuth provider
        service.setRestOperations(restOperations);
    }

    /**
     * Builds a ClientRegistration for Google with a userInfoUri pointing to a placeholder.
     */
    private ClientRegistration googleRegistration() {
        return ClientRegistration.withRegistrationId("google")
                .clientId("client-id")
                .clientSecret("client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "email", "profile")
                .authorizationUri("https://accounts.google.com/o/oauth2/auth")
                .tokenUri("https://oauth2.googleapis.com/token")
                .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
                .userNameAttributeName("sub")
                .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
                .clientName("Google")
                .build();
    }

    private OAuth2UserRequest userRequest() {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "fake-token",
                Instant.now(), Instant.now().plusSeconds(3600));
        return new OAuth2UserRequest(googleRegistration(), accessToken);
    }

    /**
     * Stubs the RestOperations to return the given user attributes from the userinfo endpoint.
     * DefaultOAuth2UserService calls exchange(RequestEntity, ParameterizedTypeReference) to fetch user info.
     */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void stubProviderUserInfo(Map<String, Object> attributes) {
        when(restOperations.exchange(any(), any(ParameterizedTypeReference.class)))
                .thenReturn((ResponseEntity) ResponseEntity.ok(attributes));
    }

    @Test
    @DisplayName("New user is created and saved when no existing user found")
    void loadUser_newUser_createdAndSaved() {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("sub", "google-123");
        attrs.put("email", "newuser@example.com");
        attrs.put("given_name", "New");
        attrs.put("family_name", "User");
        attrs.put("picture", "https://example.com/pic.jpg");
        attrs.put("email_verified", true);

        stubProviderUserInfo(attrs);
        when(userRepository.findByOauthProviderAndOauthProviderId("google", "google-123"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("newuser@example.com")).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        OAuth2User result = service.loadUser(userRequest());

        assertThat(result).isInstanceOf(OAuth2UserPrincipal.class);
        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertThat(principal.getUser().getEmail()).isEqualTo("newuser@example.com");
        assertThat(principal.getUser().getRoles()).contains(Role.USER);
        assertThat(principal.getUser().isEmailVerified()).isTrue();
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Existing user found by provider ID is updated, not re-created")
    void loadUser_existingUserByProviderId_updated() {
        User existing = User.builder()
                .id(UUID.randomUUID())
                .email("existing@example.com")
                .firstName("Old")
                .lastName("Name")
                .oauthProvider("google")
                .oauthProviderId("google-456")
                .roles(Set.of(Role.USER))
                .build();

        Map<String, Object> attrs = new HashMap<>();
        attrs.put("sub", "google-456");
        attrs.put("email", "existing@example.com");
        attrs.put("given_name", "Old");
        attrs.put("family_name", "Name");
        attrs.put("picture", "https://example.com/newpic.jpg");
        attrs.put("email_verified", true);

        stubProviderUserInfo(attrs);
        when(userRepository.findByOauthProviderAndOauthProviderId("google", "google-456"))
                .thenReturn(Optional.of(existing));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        service.loadUser(userRequest());

        // Should NOT look up by email since provider match was found
        verify(userRepository, never()).findByEmail(any());
        assertThat(existing.getProfilePictureUrl()).isEqualTo("https://example.com/newpic.jpg");
        assertThat(existing.isEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("User found by email when email_verified is null (e.g. GitHub) and linked")
    void loadUser_emailVerifiedNull_lookupByEmail() {
        User existingByEmail = User.builder()
                .id(UUID.randomUUID())
                .email("shared@example.com")
                .firstName("Shared")
                .lastName("User")
                .roles(Set.of(Role.USER))
                .build();

        Map<String, Object> attrs = new HashMap<>();
        attrs.put("sub", "google-789");
        attrs.put("email", "shared@example.com");
        // email_verified intentionally omitted (null)

        stubProviderUserInfo(attrs);
        when(userRepository.findByOauthProviderAndOauthProviderId("google", "google-789"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("shared@example.com")).thenReturn(Optional.of(existingByEmail));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        OAuth2User result = service.loadUser(userRequest());

        OAuth2UserPrincipal principal = (OAuth2UserPrincipal) result;
        assertThat(principal.getUser().getId()).isEqualTo(existingByEmail.getId());
        assertThat(existingByEmail.getOauthProvider()).isEqualTo("google");
        assertThat(existingByEmail.getOauthProviderId()).isEqualTo("google-789");
    }

    @Test
    @DisplayName("email_verified=false skips email lookup and creates new user")
    void loadUser_emailVerifiedFalse_skipEmailLookup_createNewUser() {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("sub", "google-unverified");
        attrs.put("email", "unverified@example.com");
        attrs.put("email_verified", false);

        stubProviderUserInfo(attrs);
        when(userRepository.findByOauthProviderAndOauthProviderId("google", "google-unverified"))
                .thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        service.loadUser(userRequest());

        // Must NOT attempt email lookup when email_verified is explicitly false
        verify(userRepository, never()).findByEmail(any());
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Throws OAuth2AuthenticationException when email is null")
    void loadUser_nullEmail_throwsException() {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("sub", "google-noemail");
        // no "email" key

        stubProviderUserInfo(attrs);
        when(userRepository.findByOauthProviderAndOauthProviderId(any(), any()))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUser(userRequest()))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .satisfies(ex -> assertThat(((OAuth2AuthenticationException) ex).getError().getErrorCode())
                        .contains("Email not provided"));
    }
}