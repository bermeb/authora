package dev.bermeb.authora.filter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.service.AuditLogService;
import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import jakarta.annotation.PostConstruct;
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
import java.util.Comparator;
import java.util.List;
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

    private List<String> orderedPathPrefixes = List.of();

    @PostConstruct
    void initPathPrefixes() {
        Map<String, AuthoraProperties.RateLimit.PathLimit> paths =
                properties.getRateLimit().getPaths();
        this.orderedPathPrefixes = paths.keySet().stream()
                .sorted(Comparator.comparingInt(String::length).reversed())
                .toList();
        if (orderedPathPrefixes.isEmpty() && properties.getRateLimit().isEnabled()) {
            log.warn("Rate limit is enabled but no paths are configured under " +
                    "authora.rate-limit.paths - no requests will be limited.");
        }
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws ServletException, IOException {

        if (!properties.getRateLimit().isEnabled()) {
            chain.doFilter(request, response);
            return;
        }

        String matchedPath = matchedPath(request);
        if (matchedPath == null) {
            chain.doFilter(request, response);
            return;
        }

        AuthoraProperties.RateLimit.PathLimit limit =
                properties.getRateLimit().getPaths().get(matchedPath);

        String ip = request.getRemoteAddr();
        String key = matchedPath + "|" + ip;
        Bucket bucket = resolveBucket(key, limit);

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

    private String matchedPath(HttpServletRequest request) {
        String requestPath = request.getServletPath();
        for (String prefix : orderedPathPrefixes) {
            if (requestPath.startsWith(prefix)) return prefix;
        }
        return null;
    }
}