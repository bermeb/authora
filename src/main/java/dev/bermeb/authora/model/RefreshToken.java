package dev.bermeb.authora.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh-tokens", indexes = {
        @Index(name = "idx_rt_token", columnList = "token", unique = true),
        @Index(name = "idx_rt_user", columnList = "user_id")
})
@Getter @Setter @Builder @NoArgsConstructor @AllArgsConstructor
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true, length = 64)
    private String token;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(length = 45)
    private String createdByIp;

    @Column(length = 255)
    private String userAgent;

    @Column(nullable = false)
    @Builder.Default
    private boolean revoked = false;

    @Column
    private Instant revokedAt;

    @Column(length = 100)
    private String revokedReason;

    public boolean isExpired() { return Instant.now().isAfter(expiresAt); }

    public boolean isActive() { return !revoked && !isExpired(); }

    public void revoke(String reason) {
        this.revoked = true;
        this.revokedReason = reason;
        this.revokedAt = Instant.now();
    }
}