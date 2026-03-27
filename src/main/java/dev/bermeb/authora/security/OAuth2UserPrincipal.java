package dev.bermeb.authora.security;

import dev.bermeb.authora.model.User;
import lombok.Getter;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

@Getter
public class OAuth2UserPrincipal implements OAuth2User {

    private final User user;

    private final Map<String, Object> attributes;

    private OAuth2UserPrincipal(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    public static OAuth2UserPrincipal of(User user, Map<String, Object> attributes) {
        return new OAuth2UserPrincipal(user, attributes);
    }

    @Override
    public Collection<? extends GrantedAuthority>  getAuthorities() {
        return user.getRoles().stream()
                .map(r -> new SimpleGrantedAuthority("ROLE_" + r.name()))
                .collect(Collectors.toSet());
    }

    @Override
    public Map<String, Object> getAttributes() { return attributes; }

    @Override
    @NullMarked
    public String getName() { return user.getEmail(); }

}