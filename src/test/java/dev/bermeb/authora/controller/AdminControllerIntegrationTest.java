package dev.bermeb.authora.controller;

import dev.bermeb.authora.model.Role;
import dev.bermeb.authora.repository.PasswordResetTokenRepository;
import dev.bermeb.authora.repository.RefreshTokenRepository;
import dev.bermeb.authora.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminControllerIntegrationTest {

    @MockitoBean
    JavaMailSender mailSender;
    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    UserRepository userRepository;
    @Autowired
    RefreshTokenRepository refreshTokenRepository;
    @Autowired
    PasswordResetTokenRepository passwordResetTokenRepository;

    private static final String AUTH_BASE = "/api/v1/auth";
    private static final String ADMIN_BASE = "/api/v1/admin";

    private String adminToken;
    private String normalToken;
    private UUID adminUserId;
    private UUID normalUserId;

    @BeforeEach
    void setupUsers() throws Exception {
        // Register admin user
        String adminReg = mockMvc.perform(post(AUTH_BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "admin@example.com", "password", "password12345",
                                "firstName", "Admin", "lastName", "User"
                        ))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        adminUserId = UUID.fromString(objectMapper.readTree(adminReg).get("userId").asString());

        // Promote to ADMIN via repository (same transaction, visible in subsequent MockMvc calls)
        userRepository.findById(adminUserId).ifPresent(user -> {
            user.getRoles().add(Role.ADMIN);
            userRepository.saveAndFlush(user);
        });

        // Login as admin
        String adminLogin = mockMvc.perform(post(AUTH_BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "admin@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        adminToken = objectMapper.readTree(adminLogin).get("accessToken").asString();

        // Register a user
        String normalReg = mockMvc.perform(post(AUTH_BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "normal@example.com", "password", "password12345",
                                "firstName", "Normal", "lastName", "User"
                        ))))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        normalUserId = UUID.fromString(objectMapper.readTree(normalReg).get("userId").asString());

        String normalLogin = mockMvc.perform(post(AUTH_BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "normal@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        normalToken = objectMapper.readTree(normalLogin).get("accessToken").asString();
    }

    @AfterEach
    void cleanup() {
        refreshTokenRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        userRepository.deleteAll();
    }

    @Test
    @DisplayName("GET /admin/users → 401 without auth")
    void listUsers_noAuth() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /admin/users → 403 for non-admin user")
    void listUsers_forbidden() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/users")
                        .header("Authorization", "Bearer " + normalToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /admin/users → 200 with pagination for admin")
    void listUsers_success() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.totalElements").isNumber())
                .andExpect(jsonPath("$.totalPages").isNumber());
    }

    @Test
    @DisplayName("GET /admin/users/{id} → 200 with user data")
    void getUser_found() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/users/" + adminUserId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("admin@example.com"))
                .andExpect(jsonPath("$.firstName").value("Admin"));
    }

    @Test
    @DisplayName("GET /admin/users/{id} → 404 for unknown id")
    void getUser_notFound() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/users/" + UUID.randomUUID())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("PUT /admin/users/{id}/lock?locked=true → 200 success")
    void setLock_lock() throws Exception {
        mockMvc.perform(put(ADMIN_BASE + "/users/" + normalUserId + "/lock")
                        .param("locked", "true")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("User locked"));
    }

    @Test
    @DisplayName("PUT /admin/users/{id}/lock?locked=false → 200 unlock success")
    void setLock_unlock() throws Exception {
        mockMvc.perform(put(ADMIN_BASE + "/users/" + normalUserId + "/lock")
                        .param("locked", "false")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User unlocked"));
    }

    @Test
    @DisplayName("PUT /admin/users/{id}/enable?enabled=false → 200 success")
    void setEnabled_disable() throws Exception {
        mockMvc.perform(put(ADMIN_BASE + "/users/" + normalUserId + "/enable")
                        .param("enabled", "false")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("User disabled"));
    }

    @Test
    @DisplayName("PUT /admin/users/{id}/enable?enabled=true → 200 success")
    void setEnabled_enable() throws Exception {
        mockMvc.perform(put(ADMIN_BASE + "/users/" + normalUserId + "/enable")
                        .param("enabled", "true")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("User enabled"));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/roles/ADMIN → 200 role assigned")
    void assignRole() throws Exception {
        mockMvc.perform(post(ADMIN_BASE + "/users/" + normalUserId + "/roles/ADMIN")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Role assigned"));
    }

    @Test
    @DisplayName("DELETE /admin/users/{id}/roles/USER → 200 role removed")
    void removeRole() throws Exception {
        mockMvc.perform(delete(ADMIN_BASE + "/users/" + normalUserId + "/roles/USER")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Role removed"));
    }

    @Test
    @DisplayName("POST /admin/users/{id}/revoke-sessions → 200 success")
    void revokeSessions() throws Exception {
        mockMvc.perform(post(ADMIN_BASE + "/users/" + normalUserId + "/revoke-sessions")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("All sessions revoked"));
    }

    @Test
    @DisplayName("GET /admin/audit-logs → 200 with pagination")
    void allAuditLogs() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/audit-logs")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.totalElements").isNumber());
    }

    @Test
    @DisplayName("GET /admin/audit-logs/users/{userId} → 200 with filtered logs")
    void userAuditLogs() throws Exception {
        mockMvc.perform(get(ADMIN_BASE + "/audit-logs/users/" + adminUserId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
    }
}