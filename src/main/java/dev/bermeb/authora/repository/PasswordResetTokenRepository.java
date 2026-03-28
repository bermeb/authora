package dev.bermeb.authora.repository;

import dev.bermeb.authora.model.PasswordResetToken;
import dev.bermeb.authora.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByToken(String tokenHash);

    @Modifying(clearAutomatically = true)
    @Transactional
    void deleteByUser(User user);

    @Modifying(clearAutomatically = true)
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiresAt < :cutoff OR t.used = true")
    void deleteExpiredAndUsed(Instant cutoff);

}