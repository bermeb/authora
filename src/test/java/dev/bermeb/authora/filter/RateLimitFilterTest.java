package dev.bermeb.authora.filter;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.service.AuditLogService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock
    AuthoraProperties properties;
    @Mock
    AuditLogService auditLogService;

    RateLimitFilter filter;

    private AuthoraProperties.RateLimit rateLimit;
    private Map<String, AuthoraProperties.RateLimit.PathLimit> paths;

    @BeforeEach
    void setUp() {
        paths = new HashMap<>();
        paths.put("/api/v1/auth/login", pathLimit(10, 60));

        rateLimit = new AuthoraProperties.RateLimit();
        rateLimit.setEnabled(true);
        rateLimit.setPaths(paths);
        when(properties.getRateLimit()).thenReturn(rateLimit);

        filter = newFilter();
    }

    private RateLimitFilter newFilter() {
        RateLimitFilter filter = new RateLimitFilter(properties, auditLogService, JsonMapper.builder().build());
        filter.initPathPrefixes();
        return filter;
    }

    private static AuthoraProperties.RateLimit.PathLimit pathLimit(int capacity, long periodSeconds) {
        AuthoraProperties.RateLimit.PathLimit pathLimit = new AuthoraProperties.RateLimit.PathLimit();
        pathLimit.setCapacity(capacity);
        pathLimit.setPeriodSeconds(periodSeconds);
        return pathLimit;
    }

    @Test
    @DisplayName("Rate limiting disabled → request passes through")
    void rateLimitDisabled_passesThrough() throws Exception {
        rateLimit.setEnabled(false);

        MockHttpServletRequest request = requestFor("/api/v1/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    @DisplayName("Non-rate-limited path → request passes through")
    void nonRateLimitedPath_passesThrough() throws Exception {
        MockHttpServletRequest request = requestFor("/api/v1/admin/users");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    @Test
    @DisplayName("Rate-limited path with token available → request passes through")
    void rateLimitedPath_tokenAvailable_passesThrough() throws Exception {
        MockHttpServletRequest request = requestFor("/api/v1/auth/login");
        request.setRemoteAddr("10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(chain.getRequest()).isNotNull();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        verify(auditLogService, never()).logFailure(any(), (String) any(), any(), any());
    }

    @Test
    @DisplayName("Rate-limited path with exhausted bucket → 429 and audit log")
    void rateLimitedPath_bucketExhausted_returns429() throws Exception {
        paths.put("/api/v1/auth/login", pathLimit(1, 60));
        filter = newFilter();

        MockHttpServletRequest first = requestFor("/api/v1/auth/login");
        first.setRemoteAddr("10.0.0.2");
        filter.doFilter(first, new MockHttpServletResponse(), new MockFilterChain());

        // Second request from same IP should be rate-limited
        MockHttpServletRequest second = requestFor("/api/v1/auth/login");
        second.setRemoteAddr("10.0.0.2");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(second, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS.value());
        assertThat(response.getContentType()).contains("application/json");
        assertThat(response.getContentAsString()).contains("Too many requests");
        verify(auditLogService).logFailure(any(), (String) eq(null), any(), any());
    }

    @Test
    @DisplayName("Different IPs get independent buckets")
    void differentIps_independentBuckets() throws Exception {
        paths.put("/api/v1/auth/login", pathLimit(1, 60));
        filter = newFilter();

        // Exhaust IP A
        MockHttpServletRequest requestA = requestFor("/api/v1/auth/login");
        requestA.setRemoteAddr("10.0.0.3");
        filter.doFilter(requestA, new MockHttpServletResponse(), new MockFilterChain());

        // IP B still has tokens
        MockHttpServletRequest requestB = requestFor("/api/v1/auth/login");
        requestB.setRemoteAddr("10.0.0.4");
        MockHttpServletResponse responseB = new MockHttpServletResponse();
        MockFilterChain chainB = new MockFilterChain();

        filter.doFilter(requestB, responseB, chainB);

        assertThat(chainB.getRequest()).isNotNull();
        assertThat(responseB.getStatus()).isEqualTo(HttpStatus.OK.value());
    }

    private MockHttpServletRequest requestFor(String path) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServletPath(path);
        return request;
    }
}