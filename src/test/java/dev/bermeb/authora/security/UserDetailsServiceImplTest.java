package dev.bermeb.authora.security;

import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    @Mock
    UserRepository userRepository;

    @InjectMocks
    UserDetailsServiceImpl service;

    private User buildUser(String email) {
        return User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .passwordHash("$2a$12$hash")
                .firstName("Test")
                .lastName("User")
                .emailVerified(true)
                .roles(Set.of(Role.USER))
                .build();
    }

    @Test
    @DisplayName("loadUserByUsername returns UserPrincipal when user exists")
    void loadUser_found() {
        User user = buildUser("test@example.com");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        UserDetails details = service.loadUserByUsername("test@example.com");

        assertThat(details.getUsername()).isEqualTo("test@example.com");
        assertThat(details).isInstanceOf(UserPrincipal.class);
    }

    @Test
    @DisplayName("loadUserByUsername lowercases the email before lookup")
    void loadUser_lowercasesEmail() {
        User user = buildUser("test@example.com");
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        service.loadUserByUsername("TEST@EXAMPLE.COM");

        verify(userRepository).findByEmail("test@example.com");
    }

    @Test
    @DisplayName("loadUserByUsername throws UsernameNotFoundException when user not found")
    void loadUser_notFound() {
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.loadUserByUsername("unknown@example.com"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("unknown@example.com");
    }
}