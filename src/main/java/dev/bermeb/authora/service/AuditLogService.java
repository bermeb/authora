package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.security.OAuth2UserPrincipal;
import dev.bermeb.authora.security.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogWriter auditLogWriter;
    private final AuthoraProperties properties;

    private static final int USER_AGENT_MAX_LEN = 255;

    public void log(AuditLog.AuditEventType type, User user, String details,
                    HttpServletRequest request, boolean failed) {
        if (!properties.getFeatures().isAuditLogEnabled()) return;

        User actor = currentActor();

        AuditLog entry = AuditLog.builder()
                .eventType(type)
                .userId(user != null ? user.getId() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .actorUserId(actor != null && !actorIsTarget ? actor.getId() : null)
                .actorEmail(actor != null && !actorIsTarget ? actor.getEmail() : null)
                .details(details)
                .ipAddress(extractIp(request))
                .userAgent(userAgent(request))
                .createdAt(Instant.now())
                .failed(failed)
                .build();

        auditLogWriter.write(entry);
    }

    public void logSuccess(AuditLog.AuditEventType type, User user, HttpServletRequest request) {
        log(type, user, null, request, false);
    }

    public void logSuccess(AuditLog.AuditEventType type, User user, String details, HttpServletRequest request) {
        log(type, user, details, request, false);
    }

    public void logFailure(AuditLog.AuditEventType type, User user, String details, HttpServletRequest request) {
        log(type, user, details, request, true);
    }

    public void logFailure(AuditLog.AuditEventType type, String email, String details, HttpServletRequest request) {
        if (!properties.getFeatures().isAuditLogEnabled()) return;

        AuditLog entry = AuditLog.builder()
                .eventType(type)
                .userEmail(email)
                .details(details)
                .ipAddress(extractIp(request))
                .userAgent(userAgent(request))
                .createdAt(Instant.now())
                .failed(true)
                .build();

        auditLogWriter.write(entry);
    }

    public void logSuspiciousActivity(User user, String details, HttpServletRequest request) {
        log(AuditLog.AuditEventType.SUSPICIOUS_ACTIVITY, user, details, request, true);
    }

    private User currentActor() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return null;
        Object principal = auth.getPrincipal();
        if (principal instanceof UserPrincipal up) return up.getUser();
        if (principal instanceof OAuth2UserPrincipal op) return op.getUser();
        return null;
    }

    private static String userAgent(HttpServletRequest request) {
        if (request == null) return null;
        String ua = request.getHeader("User-Agent");
        if (ua == null) return null;
        return ua.length() > USER_AGENT_MAX_LEN ? ua.substring(0, USER_AGENT_MAX_LEN) : ua;
    }

    private String extractIp(HttpServletRequest request) {
        if (request == null) return null;
        // RemoteIpValve (server.forward-headers-strategy: NATIVE) already resolves X-Forwarded-For
        // into getRemoteAddr(), so manual header parsing is unnecessary and would be inconsistent
        return request.getRemoteAddr();
    }
}