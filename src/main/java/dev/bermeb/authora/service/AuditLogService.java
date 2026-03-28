package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.model.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogWriter auditLogWriter;
    private final AuthoraProperties properties;

    public void log(AuditLog.AuditEventType type, User user, String details,
                    HttpServletRequest request, boolean failed) {
        if (!properties.getFeatures().isAuditLogEnabled()) return;

        AuditLog entry = AuditLog.builder()
                .eventType(type)
                .userId(user != null ? user.getId() : null)
                .userEmail(user != null ? user.getEmail() : null)
                .details(details)
                .ipAddress(request != null ? extractIp(request) : null)
                .userAgent(request != null ? request.getHeader("User-Agent") : null)
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
                .ipAddress(request != null ? extractIp(request) : null)
                .userAgent(request != null ? request.getHeader("User-Agent") : null)
                .createdAt(Instant.now())
                .failed(true)
                .build();

        auditLogWriter.write(entry);
    }

    private String extractIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public void logSuspiciousActivity(User user, String details, HttpServletRequest request) {
        log(AuditLog.AuditEventType.SUSPICIOUS_ACTIVITY, user, details, request, true);
    }
}