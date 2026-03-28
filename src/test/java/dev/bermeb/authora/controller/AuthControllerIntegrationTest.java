package dev.bermeb.authora.controller;

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
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthControllerIntegrationTest {

    @MockitoBean
    JavaMailSender mailSender;
    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;

    private static final String BASE = "/api/v1/auth";

    // ── Registration ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /register → 201 Created")
    void register_success() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "newuser@example.com",
                                "password", "password12345",
                                "firstName", "New",
                                "lastName", "User"
                        ))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.userId").exists());
    }

    @Test
    @DisplayName("POST /register duplicate email → 401")
    void register_duplicate() throws Exception {
        // Register first time
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "dup@example.com", "password", "password12345",
                        "firstName", "A", "lastName", "B"
                )))).andExpect(status().isCreated());

        // Register second time – same email
        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "dup@example.com", "password", "password12345",
                                "firstName", "A", "lastName", "B"
                        ))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("POST /register invalid body → 400 Validation error")
    void register_validationFail() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "not-an-email",
                                "password", "pw",
                                "firstName", "",
                                "lastName", "X"
                        ))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors").exists());
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /login → 200 + tokens")
    void login_success() throws Exception {
        // Register first
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "logintest@example.com", "password", "password12345",
                        "firstName", "Login", "lastName", "Test"
                )))).andExpect(status().isCreated());

        // Then login
        mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "logintest@example.com",
                                "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.email").value("logintest@example.com"));
    }

    @Test
    @DisplayName("POST /login wrong password → 401")
    void login_wrongPassword() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "wrongpw@example.com", "password", "correct12345",
                        "firstName", "A", "lastName", "B"
                )))).andExpect(status().isCreated());

        mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "wrongpw@example.com", "password", "WRONG"
                        ))))
                .andExpect(status().isUnauthorized());
    }

    // ── Password Reset ────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /password/forgot → 200 even for unknown email (no enumeration)")
    void forgotPassword_unknownEmail_returns200() throws Exception {
        mockMvc.perform(post(BASE + "/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "nobody@example.com"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    // ── Protected endpoints ───────────────────────────────────────────────────

    @Test
    @DisplayName("GET /me without token → 401")
    void getMe_unauthenticated() throws Exception {
        mockMvc.perform(get(BASE + "/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("GET /me with valid token → 200")
    void getMe_authenticated() throws Exception {
        // Register + login
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "metest@example.com", "password", "password12345",
                        "firstName", "Me", "lastName", "Test"
                )))).andExpect(status().isCreated());

        String response = mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "metest@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String token = objectMapper.readTree(response).get("accessToken").asString();

        mockMvc.perform(get(BASE + "/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.email").value("metest@example.com"));
    }

    // ── Token Refresh ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /refresh with valid refresh token → 200 + new accessToken")
    void refresh_success() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "refreshtest@example.com", "password", "password12345",
                        "firstName", "Refresh", "lastName", "Test"
                )))).andExpect(status().isCreated());

        String loginResp = mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "refreshtest@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String refreshToken = objectMapper.readTree(loginResp).get("refreshToken").asString();

        mockMvc.perform(post(BASE + "/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andExpect(jsonPath("$.refreshToken").exists())
                .andExpect(jsonPath("$.success").value(true));
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /logout with valid token → 200 success")
    void logout_success() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "logouttest@example.com", "password", "password12345",
                        "firstName", "Logout", "lastName", "Test"
                )))).andExpect(status().isCreated());

        String loginResp = mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "logouttest@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String accessToken = objectMapper.readTree(loginResp).get("accessToken").asString();
        String refreshToken = objectMapper.readTree(loginResp).get("refreshToken").asString();

        mockMvc.perform(post(BASE + "/logout")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("refreshToken", refreshToken))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("POST /logout/all with valid token → 200 success")
    void logoutAll_success() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "logoutalltest@example.com", "password", "password12345",
                        "firstName", "LogoutAll", "lastName", "Test"
                )))).andExpect(status().isCreated());

        String loginResp = mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "logoutalltest@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String accessToken = objectMapper.readTree(loginResp).get("accessToken").asString();

        mockMvc.perform(post(BASE + "/logout/all")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    // ── Change Password ───────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /password/change with valid credentials → 200 success")
    void changePassword_success() throws Exception {
        mockMvc.perform(post(BASE + "/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of(
                        "email", "changepw@example.com", "password", "password12345",
                        "firstName", "Change", "lastName", "PW"
                )))).andExpect(status().isCreated());

        String loginResp = mockMvc.perform(post(BASE + "/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "email", "changepw@example.com", "password", "password12345"
                        ))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String accessToken = objectMapper.readTree(loginResp).get("accessToken").asString();

        mockMvc.perform(post(BASE + "/password/change")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "currentPassword", "password12345",
                                "newPassword", "newPassword4567"
                        ))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    @DisplayName("POST /password/change without auth → 401")
    void changePassword_unauthenticated() throws Exception {
        mockMvc.perform(post(BASE + "/password/change")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "currentPassword", "password12345",
                                "newPassword", "newPassword4567"
                        ))))
                .andExpect(status().isUnauthorized());
    }
}