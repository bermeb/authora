package dev.bermeb.authora.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.security.UserPrincipalLookup;
import dev.bermeb.authora.service.AuditLogService;
import dev.bermeb.authora.service.JwtService;
import io.jsonwebtoken.JwtException;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AuditLogService auditLogService;
    private final UserPrincipalLookup userPrincipalLookup;

    private static final int MAX_AUDITS_PER_IP_PER_HOUR = 10;

    private final Cache<String, AtomicInteger> invalidTokenAuditCounters =
            Caffeine.newBuilder()
                    .expireAfterWrite(1, TimeUnit.HOURS)
                    .maximumSize(100_000)
                    .build();

    @Value("${server.forward-headers-strategy:none}")
    private String forwardHeadersStrategy;

    @PostConstruct
    void verifyForwardHeadersStrategy() {
        if (!"native".equalsIgnoreCase(forwardHeadersStrategy)
                && !"framework".equalsIgnoreCase(forwardHeadersStrategy)) {
            log.warn("server.forward-headers-strategy={} - JwtAuthenticationFilter's per-IP audit " +
                            "quota will use the proxy IP for ALL requests behind a reverse proxy, " +
                            "letting a single attacker IP exhaust everyone's quota. " +
                            "Set forward-headers-strategy=native (or framework) when running behind a trusted proxy.",
                    forwardHeadersStrategy);
        }
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);
        boolean claimsExtracted = false;

        try {
            final String userId = jwtService.extractUserId(jwt);
            claimsExtracted = true;

            if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userPrincipalLookup.loadUserById(UUID.fromString(userId));

                if (jwtService.isTokenValid(jwt, userDetails)) {
                    var authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (JwtException e) {
            // Token parsed structurally but failed signature/claims validation
            log.debug("JWT filter: {}", e.getMessage());
            auditIfUnderQuota(request, e.getMessage());
        } catch (Exception e) {
            // Other failures (e.g. UUID parse, user lookup) - only audit if the token
            // actually parsed as a JWT, to avoid attacker-driven audit floods
            log.debug("JWT filter: {}", e.getMessage());
            if (claimsExtracted) {
                auditIfUnderQuota(request, e.getMessage());
            }
        }

        chain.doFilter(request, response);
    }

    private void auditIfUnderQuota(HttpServletRequest request, String message) {
        String ip = request.getRemoteAddr();
        AtomicInteger counter = invalidTokenAuditCounters.get(ip, k -> new AtomicInteger());
        if (counter.incrementAndGet() <= MAX_AUDITS_PER_IP_PER_HOUR) {
            auditLogService.logFailure(
                    AuditLog.AuditEventType.INVALID_TOKEN, (String) null, message, request
            );
        }
    }
}