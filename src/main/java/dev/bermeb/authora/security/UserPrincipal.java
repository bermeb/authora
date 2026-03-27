package dev.bermeb.authora.security;

import dev.bermeb.authora.model.User;
import lombok.Getter;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

@Getter
public class UserPrincipal implements UserDetails {

    private final User user;

    private UserPrincipal(User user) { this.user = user; }

    public static UserPrincipal of(User user) { return new UserPrincipal(user); }

    @Override
    @NullMarked
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return user.getRoles().stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public String getPassword() { return user.getPasswordHash(); }

    @Override
    @NullMarked
    public String getUsername() { return user.getEmail(); }

    @Override
    public boolean isAccountNonLocked() { return !user.isAccountLocked(); }

    @Override
    public boolean isEnabled() { return user.isEnabled(); }

}