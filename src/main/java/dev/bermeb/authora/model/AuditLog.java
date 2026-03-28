package dev.bermeb.authora.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_al_user_id", columnList = "user_id"),
        @Index(name = "idx_al_event_type", columnList = "event_type"),
        @Index(name = "idx_al_created_at", columnList = "created_at")
})
@Getter @Builder @NoArgsConstructor @AllArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id")
    private UUID userId;

    @Column
    private String userEmail;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 60)
    private AuditEventType eventType;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(length = 45)
    private String ipAddress;

    @Column(length = 45)
    private String userAgent;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private boolean failed;

    public enum AuditEventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        TOKEN_REFRESHED,
        OAUTH2_LOGIN,
        REGISTRATION,
        EMAIL_VERIFICATION,
        PASSWORD_CHANGED,
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_REQUIRED,
        PASSWORD_RESET_COMPLETED,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        ACCOUNT_DISABLED,
        ROLE_ASSIGNED,
        ROLE_REMOVED,
        USER_DELETED,
        RATE_LIMIT_EXCEEDED,
        INVALID_TOKEN,
        SUSPICIOUS_ACTIVITY
    }
}