package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class JwtService {

    private final AuthoraProperties properties;

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList())
        );
        return buildToken(claims, userDetails.getUsername(),
                properties.getJwt().getAccessTokenExpirationMinutes() * 60_000L);
    }

    private String buildToken(Map<String, Object> claims, String email, long expirationMs) {
        return Jwts.builder()
                .claims(claims)
                .subject(email)
                .issuer(properties.getJwt().getIssuer())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(getSignKey(), Jwts.SIG.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (JwtException e) {
            log.warn("JWT validation failed: {}" ,e.getMessage());
            return false;
        }
    }

    public String extractUsername(String token) { return extractAllClaims(token).getSubject(); }

    public Date extractExpiration(String token) { return extractAllClaims(token).getExpiration(); }

    private boolean isTokenExpired(String token) { return extractExpiration(token).before(new Date()); }

    public long getAccessTokenExpirationSeconds() {
        return properties.getJwt().getAccessTokenExpirationMinutes() * 60L;
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    private SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(
                Base64.getEncoder()
                        .encodeToString(properties.getJwt().getSecret().getBytes()
                        ));
        return Keys.hmacShaKeyFor(keyBytes);
    }
}