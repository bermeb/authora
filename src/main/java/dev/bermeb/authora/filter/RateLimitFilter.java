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
import java.util.Set;
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

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws ServletException, IOException {

        if (!properties.getRateLimit().isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        Map<String, AuthoraProperties.RateLimit.PathLimit> paths =
                properties.getRateLimit().getPaths();

        String matchedPath = matchedPath(request.getServletPath(), paths.keySet());
        if (matchedPath == null) {
            chain.doFilter(request, response);
            return;
        }

        AuthoraProperties.RateLimit.PathLimit limit = paths.get(matchedPath);
        String ip = request.getRemoteAddr();
        Bucket bucket = resolveBucket(matchedPath + "|" + ip, limit);

        if (bucket.tryConsume(1)) {
            chain.doFilter(request, response);
        } else {
            log.warn("Rate limit exceeded for IP: {} path: {}", ip, matchedPath);

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

    private Bucket resolveBucket(String key, AuthoraProperties.RateLimit.PathLimit limit) {
        return localBuckets.get(key, k -> Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(limit.getCapacity())
                        .refillGreedy(limit.getCapacity(), Duration.ofSeconds(limit.getPeriodSeconds()))
                        .build())
                .build()
        );
    }

    private static String matchedPath(String requestPath, Set<String> prefixes) {
        // Longest-prefix match
        String best = null;
        for (String prefix : prefixes) {
            if (requestPath.startsWith(prefix) && (best == null || prefix.length() > best.length())) {
                best = prefix;
            }
        }
        return best;
    }
}