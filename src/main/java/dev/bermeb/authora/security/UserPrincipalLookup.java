package dev.bermeb.authora.security;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.UUID;

public interface UserPrincipalLookup {
    UserDetails loadUserById(UUID id);
}
