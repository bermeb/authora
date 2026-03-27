package dev.bermeb.authora.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.service.AuditLogService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    private final AuthoraProperties properties;
    private final AuditLogService auditLogService;
    private final ObjectMapper objectMapper;

    private final Cache<String, Bucket> localBuckets =
            Caffeine.newBuilder()
                    .expireAfterAccess(1, TimeUnit.HOURS)
                    .maximumSize(100_000)
                    .build();

    private static final String[] RATE_LIMITED_PATHS = {
            "/api/v1/auth/login",
            "/api/v1/auth/register",
            "/api/v1/auth/password/forgot",
            "/api/v1/auth/password/reset",
            "/api/v1/auth/refresh"
    };

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws ServletException, IOException {

        if (!properties.getRateLimit().isEnabled() || !isRateLimited(request)) {
            chain.doFilter(request, response);
            return;
        }

        String ip = request.getRemoteAddr();
        Bucket bucket = resolveBucket(ip);

        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for IP: {}", ip);

            auditLogService.logFailure(AuditLog.AuditEventType.RATE_LIMIT_EXCEEDED,
                    (String) null, "IP: " + ip + " path: " + request.getRequestURI(), request);

            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(response.getWriter(), Map.of(
                    "success", false,
                    "message", "Too many requests. Please slow down and try again later.",
                    "status", 429
            ));
        }
    }

    private Bucket resolveBucket(String ip) {
        return localBuckets.get(ip, this::newBucket);
    }

    private Bucket newBucket(String ip) {
        int requestsPerMinute = properties.getRateLimit().getLoginAttemptsPerMinute();
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(requestsPerMinute)
                        .refillGreedy(requestsPerMinute, Duration.ofMinutes(1))
                        .build())
                .build();
    }

    private boolean isRateLimited(HttpServletRequest request) {
        String path = request.getServletPath();
        for (String p : RATE_LIMITED_PATHS) {
            if (path.startsWith(p)) return true;
        }
        return false;
    }
}