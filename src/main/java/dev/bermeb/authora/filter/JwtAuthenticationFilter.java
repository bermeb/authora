package dev.bermeb.authora.filter;

import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.security.UserDetailsServiceImpl;
import dev.bermeb.authora.service.AuditLogService;
import dev.bermeb.authora.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final AuditLogService auditLogService;
    private final UserDetailsServiceImpl userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain)
            throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        try {
            final String userId = jwtService.extractUserId(jwt);

            if(userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserById(UUID.fromString(userId));

                if(jwtService.isTokenValid(jwt, userDetails)) {
                    var authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            log.debug("JWT filter: {}", e.getMessage());
            // Only audit if it actually looked like a JWT
            if (jwt.startsWith("ey")) {
                auditLogService.logFailure(AuditLog.AuditEventType.INVALID_TOKEN,
                        (String) null, e.getMessage(), request
                );
            }
        }

        chain.doFilter(request, response);
    }
}