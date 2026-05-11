package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuditLogWriter {

    private final AuditLogRepository auditLogRepository;
    private final AuthoraProperties properties;

    private static final Logger AUDIT_FALLBACK =
            LoggerFactory.getLogger("AUDIT_FALLBACK");

    @Async
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void write(AuditLog entry) {
        if (!properties.getFeatures().isAuditLogEnabled()) return;

        try {
            auditLogRepository.save(entry);
        } catch (Exception e) {
            AUDIT_FALLBACK.error(
                    "AUDIT_DB_FAILURE event_type={} user_id={} user_email={} actor_user_id={} " +
                            "ip={} failed={} details={} ts={} cause={}",
                    entry.getEventType(), entry.getUserId(), entry.getUserEmail(),
                    entry.getActorUserId(), entry.getIpAddress(), entry.isFailed(),
                    entry.getDetails(), java.time.Instant.now(), e.getMessage());
        }
    }
}