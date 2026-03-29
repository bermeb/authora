package dev.bermeb.authora.service;

import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.AuditLogRepository;
import dev.bermeb.authora.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final RefreshTokenService refreshTokenService;
    private final AuditLogService auditLogService;

    @Transactional
    public Optional<User> setLock(UUID id, boolean locked, HttpServletRequest request) {
        return userRepository.findById(id).map(user -> {
            user.setAccountLocked(locked);
            if (!locked) {
                user.resetFailedLoginAttempts();
                auditLogService.logSuccess(AuditLog.AuditEventType.ACCOUNT_UNLOCKED, user, request);
            } else {
                auditLogService.logSuccess(AuditLog.AuditEventType.ACCOUNT_LOCKED, user, request);
                refreshTokenService.revokeAllForUser(user);
            }
            return userRepository.save(user);
        });
    }

    @Transactional
    public Optional<User> setEnabled(UUID id, boolean enabled, HttpServletRequest request) {
        return userRepository.findById(id).map(user -> {
            user.setEnabled(enabled);
            if (!enabled) {
                auditLogService.logSuccess(AuditLog.AuditEventType.ACCOUNT_DISABLED, user, "Disabled by admin", request);
                refreshTokenService.revokeAllForUser(user);
            } else {
                auditLogService.logSuccess(AuditLog.AuditEventType.ACCOUNT_ENABLED, user, "Enabled by admin", request);
            }
            return userRepository.save(user);
        });
    }

    @Transactional
    public Optional<User> assignRole(UUID id, Role role, HttpServletRequest request) {
        return userRepository.findById(id).map(user -> {
            user.getRoles().add(role);
            auditLogService.logSuccess(AuditLog.AuditEventType.ROLE_ASSIGNED, user,
                    "Role " + role.name() + " assigned by admin", request);
            return userRepository.save(user);
        });
    }

    @Transactional
    public Optional<User> removeRole(UUID id, Role role, HttpServletRequest request) {
        return userRepository.findById(id).map(user -> {
            user.getRoles().remove(role);
            auditLogService.logSuccess(AuditLog.AuditEventType.ROLE_REMOVED, user,
                    "Role " + role.name() + " removed by admin", request);
            return userRepository.save(user);
        });
    }

    @Transactional(readOnly = true)
    public Page<User> listUsers(int page, int size) {
        return userRepository.findAll(
                PageRequest.of(page, Math.min(size, 100), Sort.by("createdAt").descending()));
    }

    @Transactional(readOnly = true)
    public Optional<User> findUser(UUID id) {
        return userRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> listAuditLogs(int page, int size) {
        return auditLogRepository.findAllByOrderByCreatedAtDesc(
                PageRequest.of(page, Math.min(size, 200)));
    }

    @Transactional(readOnly = true)
    public Page<AuditLog> listUserAuditLogs(UUID userId, int page, int size) {
        return auditLogRepository.findByUserIdOrderByCreatedAtDesc(
                userId, PageRequest.of(page, Math.min(size, 200)));
    }

    @Transactional
    public Optional<User> revokeSessions(UUID id, HttpServletRequest request) {
        return userRepository.findById(id).map(user -> {
            refreshTokenService.revokeAllForUser(user);
            auditLogService.logSuccess(AuditLog.AuditEventType.LOGOUT, user, "All sessions revoked by admin", request);
            return user;
        });
    }
}