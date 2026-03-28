package dev.bermeb.authora.security;

import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        // Let the parent class fetch the user's profile from the provider's user-information endpoint
        OAuth2User oAuth2User = super.loadUser(request);

        // Extract provider details
        String provider = request.getClientRegistration().getRegistrationId(); // e.g. "google"
        String providerId = oAuth2User.getName(); // the provider's unique user ID ("sub" claim)
        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");
        String picture = oAuth2User.getAttribute("picture");

        if (email == null) {
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        // Check if the OAuth2 provider actually verified this email address
        Boolean providerEmailVerified = oAuth2User.getAttribute("email_verified");

        // Try to find an existing user
        User user = userRepository
                .findByOauthProviderAndOauthProviderId(provider, providerId)
                .orElseGet(() -> {
                    if (Boolean.TRUE.equals(providerEmailVerified)) {
                        return userRepository.findByEmail(email.toLowerCase()).orElse(null);
                    }
                    return null;
                });

        // Register new user or refresh OAuth2 fields
        if (user == null) {
            user = User.builder()
                    .email(email.toLowerCase())
                    .firstName(firstName != null ? firstName : "")
                    .lastName(lastName != null ? lastName : "")
                    .emailVerified(Boolean.TRUE.equals(providerEmailVerified))
                    .oauthProvider(provider)
                    .oauthProviderId(providerId)
                    .profilePictureUrl(picture)
                    .roles(Set.of(Role.USER))
                    .build();
            log.info("Registering new OAuth2 user: {} via {}", email, provider);
        } else {
            user.setOauthProvider(provider);
            user.setOauthProviderId(providerId);
            if (picture != null) user.setProfilePictureUrl(picture);
            if (Boolean.TRUE.equals(providerEmailVerified)) {
                user.setEmailVerified(true);
            }
        }

        user = userRepository.save(user);

        // Return a principal that wraps our user entity plus the raw provider attributes
        return OAuth2UserPrincipal.of(user, oAuth2User.getAttributes());
    }
}