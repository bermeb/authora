package dev.bermeb.authora.security;

import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class OAuth2UserPrincipalTest {

    private User user;
    private Map<String, Object> attributes;
    private OAuth2UserPrincipal principal;

    @BeforeEach
    void setUp() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("oauth@example.com")
                .firstName("OAuth")
                .lastName("User")
                .roles(Set.of(Role.USER))
                .build();

        attributes = Map.of("sub", "12345", "email", "oauth@example.com");
        principal = OAuth2UserPrincipal.of(user, attributes);
    }

    @Test
    @DisplayName("of() creates instance wrapping the user and attributes")
    void of_createsInstance() {
        assertThat(principal).isNotNull();
        assertThat(principal.getUser()).isSameAs(user);
    }

    @Test
    @DisplayName("getName() returns user email")
    void getName_returnsEmail() {
        assertThat(principal.getName()).isEqualTo("oauth@example.com");
    }

    @Test
    @DisplayName("getAttributes() returns the provided attributes map")
    void getAttributes_returnsMap() {
        assertThat(principal.getAttributes()).isSameAs(attributes);
    }

    @Test
    @DisplayName("getAuthorities() contains ROLE_USER for a USER role")
    void getAuthorities_containsRoleUser() {
        Collection<? extends GrantedAuthority> authorities = principal.getAuthorities();

        assertThat(authorities)
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER");
    }

    @Test
    @DisplayName("getAuthorities() contains all user roles prefixed with ROLE_")
    void getAuthorities_multipleRoles() {
        user = User.builder()
                .id(UUID.randomUUID())
                .email("admin@example.com")
                .firstName("Admin")
                .lastName("User")
                .roles(Set.of(Role.USER, Role.ADMIN))
                .build();
        OAuth2UserPrincipal adminPrincipal = OAuth2UserPrincipal.of(user, Map.of());

        assertThat(adminPrincipal.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }
}