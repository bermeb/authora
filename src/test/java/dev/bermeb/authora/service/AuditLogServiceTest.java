package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.model.User;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuditLogServiceTest {

    @Mock
    AuditLogWriter auditLogWriter;
    @Mock
    AuthoraProperties properties;
    @Mock
    HttpServletRequest request;

    @InjectMocks
    AuditLogService auditLogService;

    private User testUser;
    private AuthoraProperties.Features features;

    @BeforeEach
    void setup() {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .email("audit@example.com")
                .build();

        features = new AuthoraProperties.Features();
        features.setAuditLogEnabled(true);
        when(properties.getFeatures()).thenReturn(features);
        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        when(request.getHeader("User-Agent")).thenReturn("TestAgent");
    }

    @Test
    @DisplayName("log() builds and delegates entry when audit is enabled")
    void log_savesWhenEnabled() {
        auditLogService.log(AuditLog.AuditEventType.LOGIN_SUCCESS, testUser, "details", request, false);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        AuditLog saved = captor.getValue();
        assertThat(saved.getEventType()).isEqualTo(AuditLog.AuditEventType.LOGIN_SUCCESS);
        assertThat(saved.getUserEmail()).isEqualTo("audit@example.com");
        assertThat(saved.getUserId()).isEqualTo(testUser.getId());
        assertThat(saved.isFailed()).isFalse();
        assertThat(saved.getIpAddress()).isEqualTo("10.0.0.1");
    }

    @Test
    @DisplayName("log() skips when audit is disabled")
    void log_skipsWhenDisabled() {
        features.setAuditLogEnabled(false);

        auditLogService.log(AuditLog.AuditEventType.LOGIN_SUCCESS, testUser, null, request, false);

        verify(auditLogWriter, never()).write(any());
    }

    @Test
    @DisplayName("logSuccess() delegates entry with failed=false")
    void logSuccess_notFailed() {
        auditLogService.logSuccess(AuditLog.AuditEventType.REGISTRATION, testUser, request);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().isFailed()).isFalse();
        assertThat(captor.getValue().getEventType()).isEqualTo(AuditLog.AuditEventType.REGISTRATION);
    }

    @Test
    @DisplayName("logSuccess(details) delegates entry with details")
    void logSuccess_withDetails() {
        auditLogService.logSuccess(AuditLog.AuditEventType.LOGOUT, testUser, "All sessions", request);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().getDetails()).isEqualTo("All sessions");
        assertThat(captor.getValue().isFailed()).isFalse();
    }

    @Test
    @DisplayName("logFailure(User) delegates entry with failed=true")
    void logFailure_userOverload_isFailed() {
        auditLogService.logFailure(AuditLog.AuditEventType.LOGIN_FAILURE, testUser, "bad creds", request);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().isFailed()).isTrue();
        assertThat(captor.getValue().getDetails()).isEqualTo("bad creds");
    }

    @Test
    @DisplayName("logFailure(email) delegates with email, no userId")
    void logFailure_emailOverload() {
        auditLogService.logFailure(AuditLog.AuditEventType.LOGIN_FAILURE, "ghost@example.com", "not found", request);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().getUserEmail()).isEqualTo("ghost@example.com");
        assertThat(captor.getValue().getUserId()).isNull();
        assertThat(captor.getValue().isFailed()).isTrue();
    }

    @Test
    @DisplayName("logFailure(email) skips when audit is disabled")
    void logFailure_emailOverload_skipsWhenDisabled() {
        features.setAuditLogEnabled(false);

        auditLogService.logFailure(AuditLog.AuditEventType.LOGIN_FAILURE, "ghost@example.com", "not found", request);

        verify(auditLogWriter, never()).write(any());
    }

    @Test
    @DisplayName("logSuspiciousActivity() delegates with SUSPICIOUS_ACTIVITY event type")
    void logSuspicious_correctType() {
        auditLogService.logSuspiciousActivity(testUser, "reuse detected", request);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().getEventType()).isEqualTo(AuditLog.AuditEventType.SUSPICIOUS_ACTIVITY);
        assertThat(captor.getValue().isFailed()).isTrue();
    }

    @Test
    @DisplayName("log() handles null request gracefully without NPE")
    void log_nullRequest_noNpe() {
        assertThatCode(() ->
                auditLogService.log(AuditLog.AuditEventType.EMAIL_VERIFICATION, testUser, null, null, false)
        ).doesNotThrowAnyException();

        verify(auditLogWriter).write(any());
    }

    @Test
    @DisplayName("log() handles null user gracefully without NPE")
    void log_nullUser_noNpe() {
        assertThatCode(() ->
                auditLogService.log(AuditLog.AuditEventType.RATE_LIMIT_EXCEEDED, null, "anon", request, true)
        ).doesNotThrowAnyException();

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().getUserId()).isNull();
        assertThat(captor.getValue().getUserEmail()).isNull();
    }

    @Test
    @DisplayName("log() extracts first IP from X-Forwarded-For header")
    void log_xForwardedFor() {
        when(request.getHeader("X-Forwarded-For")).thenReturn("1.2.3.4, 5.6.7.8");

        auditLogService.log(AuditLog.AuditEventType.LOGIN_SUCCESS, testUser, null, request, false);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogWriter).write(captor.capture());
        assertThat(captor.getValue().getIpAddress()).isEqualTo("1.2.3.4");
    }
}