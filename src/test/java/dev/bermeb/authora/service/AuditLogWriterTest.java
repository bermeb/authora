package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuditLogWriterTest {

    @Mock
    AuditLogRepository auditLogRepository;
    @Mock
    AuthoraProperties properties;

    @InjectMocks
    AuditLogWriter auditLogWriter;

    private AuthoraProperties.Features features;

    @BeforeEach
    void setup() {
        features = new AuthoraProperties.Features();
        features.setAuditLogEnabled(true);
        when(properties.getFeatures()).thenReturn(features);
    }

    @Test
    @DisplayName("write() saves entry when audit is enabled")
    void write_savesWhenEnabled() {
        AuditLog entry = AuditLog.builder()
                .eventType(AuditLog.AuditEventType.LOGIN_SUCCESS)
                .userId(UUID.randomUUID())
                .userEmail("test@example.com")
                .createdAt(Instant.now())
                .failed(false)
                .build();

        auditLogWriter.write(entry);

        verify(auditLogRepository).save(entry);
    }

    @Test
    @DisplayName("write() skips saving when audit is disabled")
    void write_skipsWhenDisabled() {
        features.setAuditLogEnabled(false);

        AuditLog entry = AuditLog.builder()
                .eventType(AuditLog.AuditEventType.LOGIN_SUCCESS)
                .createdAt(Instant.now())
                .build();

        auditLogWriter.write(entry);

        verify(auditLogRepository, never()).save(any());
    }

    @Test
    @DisplayName("write() catches repository exceptions without re-throwing")
    void write_catchesExceptions() {
        when(auditLogRepository.save(any())).thenThrow(new RuntimeException("DB down"));

        AuditLog entry = AuditLog.builder()
                .eventType(AuditLog.AuditEventType.LOGIN_SUCCESS)
                .createdAt(Instant.now())
                .build();

        // Should not throw
        auditLogWriter.write(entry);

        verify(auditLogRepository).save(entry);
    }
}