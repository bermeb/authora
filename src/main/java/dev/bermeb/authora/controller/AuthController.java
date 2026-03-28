package dev.bermeb.authora.controller;

import dev.bermeb.authora.dto.*;
import dev.bermeb.authora.model.User;
import dev.bermeb.authora.security.UserPrincipal;
import dev.bermeb.authora.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.ZoneOffset;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(
            @Valid @RequestBody RegisterRequest body,
            HttpServletRequest request) {
        User user = authService.register(
                body.getEmail(), body.getPassword(), body.getFirstName(), body.getLastName(), request
        );

        RegisterResponse response = new RegisterResponse();
        response.setSuccess(true);
        response.setMessage("Registration successful. Please verify your email.");
        response.setUserId(user.getId());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody LoginRequest body,
            HttpServletRequest request) {
        Map<String, Object> tokens = authService.login(body.getEmail(), body.getPassword(), request);
        User user = (User) tokens.get("user");

        TokenResponse response = new TokenResponse();
        response.setSuccess(true);
        response.setAccessToken((String) tokens.get("accessToken"));
        response.setRefreshToken((String) tokens.get("refreshToken"));
        response.setTokenType(TokenResponse.TokenTypeEnum.BEARER);
        response.setExpiresIn(((Number) tokens.get("expiresIn")).intValue());
        response.setUser(toUserProfile(user));

        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenRefreshResponse> refresh(
            @Valid @RequestBody RefreshRequest body,
            HttpServletRequest request) {
        Map<String, Object> result = authService.refresh(body.getRefreshToken(), request);

        return getTokenRefreshResponseResponseEntity(result);
    }

    @PostMapping("/logout")
    public ResponseEntity<SuccessResponse> logout(
            @Valid @RequestBody RefreshRequest body,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {
        authService.logout(body.getRefreshToken(), principal.getUser(), request);
        SuccessResponse response = new SuccessResponse();
        response.setSuccess(true);
        response.setMessage("Logged out successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout/all")
    public ResponseEntity<SuccessResponse> logoutAll(
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {
        authService.logoutAll(principal.getUser(), request);
        SuccessResponse response = new SuccessResponse();
        response.setSuccess(true);
        response.setMessage("All sessions terminated");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/email/verify")
    public ResponseEntity<SuccessResponse> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        SuccessResponse response = new SuccessResponse();
        response.setSuccess(true);
        response.setMessage("Email verified successfully");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<SuccessResponse> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest body,
            HttpServletRequest request) {
        authService.requestPasswordReset(body.getEmail(), request);
        SuccessResponse response = new SuccessResponse();
        response.setSuccess(true);
        response.setMessage("If that email is registered you will receive a reset link shortly.");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/password/reset")
    public ResponseEntity<SuccessResponse> resetPassword(
            @Valid @RequestBody ResetPasswordRequest body) {
        authService.resetPassword(body.getToken(), body.getNewPassword());
        SuccessResponse response = new SuccessResponse();
        response.setSuccess(true);
        response.setMessage("Password reset successfully. Please log in again.");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/password/change")
    public ResponseEntity<SuccessResponse> changePassword(
            @Valid @RequestBody ChangePasswordRequest body,
            @AuthenticationPrincipal UserPrincipal principal,
            HttpServletRequest request) {
        authService.changePassword(
                principal.getUser(), body.getCurrentPassword(), body.getNewPassword(), request
        );
        SuccessResponse response = new SuccessResponse();
        response.setSuccess(true);
        response.setMessage("Password changed. Please log in again.");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/oauth2/exchange")
    public ResponseEntity<TokenRefreshResponse> oauth2Exchange(
            @RequestBody Map<String, String> body) {
        String code = body.get("code");
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().build();
        }

        Map<String, Object> tokens = authService.exchangeOAuth2Code(code);

        return getTokenRefreshResponseResponseEntity(tokens);
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(
            @AuthenticationPrincipal UserPrincipal principal) {
        MeResponse response = new MeResponse();
        response.setSuccess(true);
        response.setUser(toUserProfile(principal.getUser()));
        return ResponseEntity.ok(response);
    }

    @NonNull
    private ResponseEntity<TokenRefreshResponse> getTokenRefreshResponseResponseEntity(Map<String, Object> result) {
        TokenRefreshResponse response = new TokenRefreshResponse();
        response.setSuccess(true);
        response.setAccessToken((String) result.get("accessToken"));
        response.setRefreshToken((String) result.get("refreshToken"));
        response.setTokenType(TokenRefreshResponse.TokenTypeEnum.BEARER);
        response.setExpiresIn(((Number) result.get("expiresIn")).intValue());

        return ResponseEntity.ok(response);
    }

    private UserProfile toUserProfile(User user) {
        UserProfile profile = new UserProfile();
        profile.setId(user.getId());
        profile.setEmail(user.getEmail());
        profile.setFirstName(user.getFirstName());
        profile.setLastName(user.getLastName());
        profile.setEmailVerified(user.isEmailVerified());
        profile.setRoles(user.getRoles().stream()
                .map(r -> UserProfile.RolesEnum.fromValue(r.name()))
                .collect(Collectors.toList()));
        // Convert profile picture URL string to URI (or null if not set)
        profile.setProfilePicture(user.getProfilePictureUrl() != null
                ? java.net.URI.create(user.getProfilePictureUrl()) : null);
        // Convert Instant to OffsetDateTime with UTC offset for the OpenAPI contract
        profile.setCreatedAt(user.getCreatedAt().atOffset(ZoneOffset.UTC));
        profile.setLastLoginAt(user.getLastLoginAt() != null
                ? user.getLastLoginAt().atOffset(ZoneOffset.UTC) : null);
        return profile;
    }
}