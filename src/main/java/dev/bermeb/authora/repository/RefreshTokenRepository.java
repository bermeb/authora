package dev.bermeb.authora.repository;

import dev.bermeb.authora.model.RefreshToken;
import dev.bermeb.authora.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByToken(String tokenHash);

    List<RefreshToken> findByUserAndRevokedFalseOrderByCreatedAtAsc(User user);

    long countByUserAndRevokedFalse(User user);

    @Modifying(clearAutomatically = true)
    @Query("UPDATE RefreshToken rt SET rt.revoked = true, rt.revokedAt = :now, rt.revokedReason = :reason " +
            "WHERE rt.user = :user AND rt.revoked = false")
    void revokeAllForUser(User user, Instant now, String reason);

    @Modifying(clearAutomatically = true)
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :cutoff OR (rt.revoked = true AND rt.revokedAt < :cutoff)")
    void deleteExpiredAndRevoked(Instant cutoff);
}