package dev.bermeb.authora.security;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.UserRepository;
import dev.bermeb.authora.service.EmailVerificationService;
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
    private final EmailVerificationService emailVerificationService;
    private final AuthoraProperties properties;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(request);

        String provider = request.getClientRegistration().getRegistrationId();
        String providerId = oAuth2User.getName();
        String email = oAuth2User.getAttribute("email");
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");
        String picture = oAuth2User.getAttribute("picture");

        if (email == null) {
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        // Only an explicit `true` from the provider is enough to skip our own verification
        // Providers that don't send `email_verified` (e.g. GitHub via /userinfo) are treated
        // the same as `false`: we still let the user in, but we send a verification email
        // and refuse to link to any pre-existing local account with the same address
        Boolean providerEmailVerified = oAuth2User.getAttribute("email_verified");
        boolean emailTrusted = Boolean.TRUE.equals(providerEmailVerified);

        User user = userRepository
                .findByOauthProviderAndOauthProviderId(provider, providerId)
                .orElse(null);

        if (user == null && emailTrusted) {
            user = userRepository.findByEmail(email.toLowerCase()).orElse(null);
        }

        boolean isNewUser = (user == null);
        if (isNewUser) {
            user = User.builder()
                    .email(email.toLowerCase())
                    .firstName(firstName != null ? firstName : "")
                    .lastName(lastName != null ? lastName : "")
                    .emailVerified(emailTrusted)
                    .oauthProvider(provider)
                    .oauthProviderId(providerId)
                    .profilePictureUrl(picture)
                    .roles(Set.of(Role.USER))
                    .build();
            log.info("Registering new OAuth2 user via {}", provider);
            log.debug("New OAuth2 user email: {}", email);
        } else {
            if (user.isLocalUser() && !user.isEmailVerified()) {
                log.warn("OAuth2 link adopting unverified local account for {} via {}; clearing password",
                        email, provider);
                user.setPasswordHash(null);
            }
            user.setOauthProvider(provider);
            user.setOauthProviderId(providerId);
            if (picture != null) user.setProfilePictureUrl(picture);
            if (emailTrusted) {
                user.setEmailVerified(true);
            }
        }

        user = userRepository.save(user);

        if (isNewUser && !emailTrusted && properties.getFeatures().isEmailVerificationRequired()) {
            log.info("OAuth2 provider {} did not verify email - issuing our own verification", provider);
            emailVerificationService.issueFor(user);
        }

        return OAuth2UserPrincipal.of(user, oAuth2User.getAttributes());
    }
}