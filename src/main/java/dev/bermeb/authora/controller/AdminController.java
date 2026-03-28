package dev.bermeb.authora.controller;

import dev.bermeb.authora.dto.*;
import dev.bermeb.authora.model.AuditLog;
import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.repository.AuditLogRepository;
import dev.bermeb.authora.repository.UserRepository;
import dev.bermeb.authora.service.AdminService;
import dev.bermeb.authora.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Min;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.time.ZoneOffset;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Validated
public class AdminController {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final AdminService adminService;

    @GetMapping("/users")
    public ResponseEntity<PaginatedUserResponse> listUsers(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "20") @Min(1) int size) {
        // Cap size to 100 to prevent accidentally returning the entire user table
        Page<User> userPage = userRepository.findAll(PageRequest.of(
                page, Math.min(size, 100), Sort.by("createdAt").descending()));

        return ResponseEntity.ok(toPaginatedUserResponse(userPage));
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<AdminUserView> getUser(@PathVariable UUID id) {
        return userRepository.findById(id)
                .map(user -> ResponseEntity.ok(toAdminUserView(user)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/users/{id}/lock")
    public ResponseEntity<SuccessResponse> setLock(
            @PathVariable UUID id,
            @RequestParam boolean locked,
            HttpServletRequest request) {
        return adminService.setLock(id, locked, request).map(user -> {
            SuccessResponse resp = new SuccessResponse();
            resp.setSuccess(true);
            resp.setMessage("User " + (locked ? "locked" : "unlocked"));
            return ResponseEntity.ok(resp);
        }).orElse(ResponseEntity.notFound().build());
    }


    @PutMapping("/users/{id}/enable")
    public ResponseEntity<SuccessResponse> setEnabled(
            @PathVariable UUID id,
            @RequestParam boolean enabled,
            HttpServletRequest request) {
        return adminService.setEnabled(id, enabled, request).map(user -> {
            SuccessResponse resp = new SuccessResponse();
            resp.setSuccess(true);
            resp.setMessage("User " + (enabled ? "enabled" : "disabled"));
            return ResponseEntity.ok(resp);
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/{id}/roles/{role}")
    public ResponseEntity<SuccessResponse> assignRole(
            @PathVariable UUID id,
            @PathVariable Role role,
            HttpServletRequest request) {
        return adminService.assignRole(id, role, request).map(user -> {
            SuccessResponse resp = new SuccessResponse();
            resp.setSuccess(true);
            resp.setMessage("Role assigned");
            return ResponseEntity.ok(resp);
        }).orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/users/{id}/roles/{role}")
    public ResponseEntity<SuccessResponse> removeRole(
            @PathVariable UUID id,
            @PathVariable Role role,
            HttpServletRequest request) {
        return adminService.removeRole(id, role, request).map(user -> {
            SuccessResponse resp = new SuccessResponse();
            resp.setSuccess(true);
            resp.setMessage("Role removed");
            return ResponseEntity.ok(resp);
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/users/{id}/revoke-sessions")
    public ResponseEntity<SuccessResponse> revokeSessions(
            @PathVariable UUID id,
            HttpServletRequest request) {
        return adminService.revokeSessions(id, request).map(user -> {
            SuccessResponse resp = new SuccessResponse();
            resp.setSuccess(true);
            resp.setMessage("All sessions revoked");
            return ResponseEntity.ok(resp);
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/audit-logs")
    public ResponseEntity<PaginatedAuditLog> allAuditLogs(
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "50") @Min(1) int size) {
        Page<AuditLog> auditLogs = auditLogRepository.findAllByOrderByCreatedAtDesc(
                PageRequest.of(page, Math.min(size, 200)));
        return ResponseEntity.ok(toPaginatedAuditLog(auditLogs));
    }

    @GetMapping("/audit-logs/users/{userId}")
    public ResponseEntity<PaginatedAuditLog> userAuditLogs(
            @PathVariable UUID userId,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "50") @Min(1) int size) {
        Page<AuditLog> auditLogs = auditLogRepository.findByUserIdOrderByCreatedAtDesc(
                userId, PageRequest.of(page, Math.min(size, 200)));
        return ResponseEntity.ok(toPaginatedAuditLog(auditLogs));
    }

    private PaginatedUserResponse toPaginatedUserResponse(Page<User> page) {
        PaginatedUserResponse response = new PaginatedUserResponse();
        response.setContent(page.getContent().stream()
                .map(this::toAdminUserView)
                .collect(Collectors.toList()));
        response.setTotalElements((int) page.getTotalElements());
        response.setTotalPages(page.getTotalPages());
        response.setNumber(page.getNumber());
        response.setSize(page.getSize());
        return response;
    }

    private AdminUserView toAdminUserView(User user) {
        AdminUserView view = new AdminUserView();
        view.setId(user.getId());
        view.setEmail(user.getEmail());
        view.setFirstName(user.getFirstName());
        view.setLastName(user.getLastName());
        view.setEmailVerified(user.isEmailVerified());
        view.setRoles(user.getRoles().stream()
                .map(r -> AdminUserView.RolesEnum.fromValue(r.name()))
                .collect(Collectors.toList()));
        view.setProfilePicture(user.getProfilePictureUrl() != null
                ? java.net.URI.create(user.getProfilePictureUrl()) : null);
        view.setCreatedAt(user.getCreatedAt().atOffset(ZoneOffset.UTC));
        view.setLastLoginAt(user.getLastLoginAt() != null
                ? user.getLastLoginAt().atOffset(ZoneOffset.UTC) : null);

        // Admin-only fields
        view.setEnabled(user.isEnabled());
        view.setAccountLocked(user.isAccountLocked());
        view.setLockedUntil(user.getLockedUntil() != null
                ? user.getLockedUntil().atOffset(ZoneOffset.UTC) : null);
        view.setFailedLoginAttempts(user.getFailedLoginAttempts());
        view.setOauthProvider(user.getOauthProvider());

        return view;
    }

    private PaginatedAuditLog toPaginatedAuditLog(Page<AuditLog> page) {
        PaginatedAuditLog log = new PaginatedAuditLog();
        log.setContent(page.getContent().stream()
                .map(this::toAuditLogEntry)
                .collect(Collectors.toList()));
        log.setTotalElements((int) page.getTotalElements());
        log.setTotalPages(page.getTotalPages());
        log.setNumber(page.getNumber());
        log.setSize(page.getSize());
        return log;
    }

    private AuditLogEntry toAuditLogEntry(AuditLog log) {
        AuditLogEntry entry = new AuditLogEntry();
        entry.setId(log.getId());
        entry.setUserId(log.getUserId());
        entry.setUserEmail(log.getUserEmail());
        entry.setEventType(AuditLogEntry.EventTypeEnum.fromValue(log.getEventType().name()));
        entry.setDetails(log.getDetails());
        entry.setIpAddress(log.getIpAddress());
        entry.setFailed(log.isFailed());
        // Convert Instant to OffsetDateTime (UTC) for the OpenAPI contract
        entry.setCreatedAt(log.getCreatedAt().atOffset(ZoneOffset.UTC));
        return entry;
    }
}