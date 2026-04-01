package dev.bermeb.authora.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
    }

    // Returns a dummy MethodParameter to satisfy the @NotNull constructor arg
    private MethodParameter dummyMethodParameter() throws NoSuchMethodException {
        return new MethodParameter(Object.class.getMethod("toString"), -1);
    }

    @Test
    @DisplayName("AuthException → correct status and URI")
    void handleAuthException() {
        AuthException ex = new AuthException("Bad token", HttpStatus.UNAUTHORIZED);

        ProblemDetail pd = handler.handleAuthException(ex);

        assertThat(pd.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(pd.getDetail()).isEqualTo("Bad token");
        assertThat(pd.getType()).isEqualTo(URI.create("https://authora.bermeb.dev/errors/auth-error"));
        assertThat(pd.getProperties()).isNotNull().containsKey("timestamp");
    }

    @Test
    @DisplayName("MethodArgumentNotValidException → 400 with field errors map")
    void handleValidation() throws Exception {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "obj");
        bindingResult.addError(new FieldError("obj", "email", "must not be blank"));
        bindingResult.addError(new FieldError("obj", "password", "too short"));

        MethodArgumentNotValidException ex =
                new MethodArgumentNotValidException(dummyMethodParameter(), bindingResult);

        ProblemDetail pd = handler.handleValidation(ex);

        assertThat(pd.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(pd.getDetail()).isEqualTo("Validation failed");
        assertThat(pd.getType()).isEqualTo(URI.create("https://authora.bermeb.dev/errors/validation-error"));

        var props = pd.getProperties();
        assertThat(props).isNotNull().containsKey("errors");
        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) Objects.requireNonNull(props).get("errors");
        assertThat(errors)
                .containsEntry("email", "must not be blank")
                .containsEntry("password", "too short");
    }

    @Test
    @DisplayName("MethodArgumentNotValidException with duplicate field keeps first message")
    void handleValidation_duplicateField_keepFirst() throws Exception {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "obj");
        bindingResult.addError(new FieldError("obj", "email", "first message"));
        bindingResult.addError(new FieldError("obj", "email", "second message"));

        MethodArgumentNotValidException ex =
                new MethodArgumentNotValidException(dummyMethodParameter(), bindingResult);

        ProblemDetail pd = handler.handleValidation(ex);

        var props = pd.getProperties();
        assertThat(props).isNotNull();
        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) Objects.requireNonNull(props).get("errors");
        assertThat(errors.get("email")).isEqualTo("first message");
    }

    @Test
    @DisplayName("ConstraintViolationException → 400 with violations map")
    void handleConstraintViolation() {
        ConstraintViolation<?> violation = mock(ConstraintViolation.class);
        Path path = mock(Path.class);
        when(path.toString()).thenReturn("field1");
        when(violation.getPropertyPath()).thenReturn(path);
        when(violation.getMessage()).thenReturn("must not be null");

        ConstraintViolationException ex = new ConstraintViolationException(Set.of(violation));

        ProblemDetail pd = handler.handleConstraintViolation(ex);

        assertThat(pd.getStatus()).isEqualTo(HttpStatus.BAD_REQUEST.value());
        assertThat(pd.getType()).isEqualTo(URI.create("https://authora.bermeb.dev/errors/validation-error"));

        var props = pd.getProperties();
        assertThat(props).isNotNull().containsKey("errors");
        @SuppressWarnings("unchecked")
        Map<String, String> errors = (Map<String, String>) Objects.requireNonNull(props).get("errors");
        assertThat(errors).containsEntry("field1", "must not be null");
    }

    @Test
    @DisplayName("AccessDeniedException → 403 Forbidden")
    void handleAccessDenied() {
        AccessDeniedException ex = new AccessDeniedException("Forbidden");

        ProblemDetail pd = handler.handleAccessDenied(ex);

        assertThat(pd.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(pd.getDetail()).isEqualTo("Access denied");
        assertThat(pd.getType()).isEqualTo(URI.create("https://authora.bermeb.dev/errors/forbidden"));
        assertThat(pd.getProperties()).isNotNull().containsKey("timestamp");
    }

    @Test
    @DisplayName("AuthenticationException → 401 Unauthorized")
    void handleSpringAuth() {
        BadCredentialsException ex = new BadCredentialsException("Bad credentials");

        ProblemDetail pd = handler.handleSpringAuth(ex);

        assertThat(pd.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED.value());
        assertThat(pd.getDetail()).isEqualTo("Authentication failed");
        assertThat(pd.getType()).isEqualTo(URI.create("https://authora.bermeb.dev/errors/unauthenticated"));
        assertThat(pd.getProperties()).isNotNull().containsKey("timestamp");
    }

    @Test
    @DisplayName("Generic Exception → 500 Internal Server Error")
    void handleGeneric() {
        RuntimeException ex = new RuntimeException("Something broke");

        ProblemDetail pd = handler.handleGeneric(ex);

        assertThat(pd.getStatus()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
        assertThat(pd.getDetail()).isEqualTo("An unexpected error occurred");
        assertThat(pd.getType()).isEqualTo(URI.create("https://authora.bermeb.dev/errors/internal-error"));
        assertThat(pd.getProperties()).isNotNull().containsKey("timestamp");
    }
}