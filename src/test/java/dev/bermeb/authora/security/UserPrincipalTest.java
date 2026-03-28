package dev.bermeb.authora.security;

import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

public class UserPrincipalTest {

    private User buildUser(Set<Role> roles, boolean locked, boolean enabled) {
        return User.builder()
                .id(UUID.randomUUID())
                .email("u@example.com")
                .passwordHash("$hash")
                .firstName("A")
                .lastName("B")
                .roles(roles)
                .accountLocked(locked)
                .enabled(enabled)
                .build();
    }

    @Test
    @DisplayName("getAuthorities() prefixes each role with ROLE_")
    void getAuthorities_prefixed() {
        UserPrincipal principal = UserPrincipal.of(buildUser(Set.of(Role.USER), false, true));
        Set<String> authorities = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("getAuthorities() contains ROLE_ADMIN for admin user")
    void getAuthorities_admin() {
        UserPrincipal principal = UserPrincipal.of(buildUser(Set.of(Role.ADMIN), false, true));
        Set<String> authorities = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        assertThat(authorities).containsExactly("ROLE_ADMIN");
    }

    @Test
    @DisplayName("getAuthorities() returns all roles when user has multiple")
    void getAuthorities_multipleRoles() {
        UserPrincipal principal = UserPrincipal.of(buildUser(Set.of(Role.USER, Role.ADMIN), false, true));
        Set<String> authorities = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
    }

    @Test
    @DisplayName("isAccountNonLocked() is true when accountLocked=false")
    void isAccountNonLocked_notLocked() {
        assertThat(UserPrincipal.of(buildUser(Set.of(Role.USER), false, true)).isAccountNonLocked())
                .isTrue();
    }

    @Test
    @DisplayName("isAccountNonLocked() is false when accountLocked=true")
    void isAccountNonLocked_locked() {
        assertThat(UserPrincipal.of(buildUser(Set.of(Role.USER), true, true)).isAccountNonLocked())
                .isFalse();
    }

    @Test
    @DisplayName("isEnabled() returns true when user is enabled")
    void isEnabled_true() {
        assertThat(UserPrincipal.of(buildUser(Set.of(Role.USER), false, true)).isEnabled())
                .isTrue();
    }

    @Test
    @DisplayName("isEnabled() returns false when user is disabled")
    void isEnabled_false() {
        assertThat(UserPrincipal.of(buildUser(Set.of(Role.USER), false, false)).isEnabled())
                .isFalse();
    }

    @Test
    @DisplayName("getUsername() returns the user's email")
    void getUsername_returnsEmail() {
        assertThat(UserPrincipal.of(buildUser(Set.of(Role.USER), false, true)).getUsername())
                .isEqualTo("u@example.com");
    }

    @Test
    @DisplayName("getUser() returns the wrapped user entity")
    void getUser_returnsWrapped() {
        User user = buildUser(Set.of(Role.USER), false, true);
        assertThat(UserPrincipal.of(user).getUser()).isSameAs(user);
    }
}