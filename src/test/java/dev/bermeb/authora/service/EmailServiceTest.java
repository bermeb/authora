package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.User;
import jakarta.mail.internet.MimeMessage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.mail.javamail.JavaMailSender;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.IContext;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class EmailServiceTest {

    @Mock
    JavaMailSender mailSender;
    @Mock
    TemplateEngine templateEngine;
    @Mock
    AuthoraProperties properties;

    @InjectMocks
    EmailService emailService;

    private User testUser;

    @BeforeEach
    void setup() throws Exception {
        testUser = User.builder()
                .id(UUID.randomUUID())
                .email("u@example.com")
                .firstName("Jane")
                .lastName("Doe")
                .build();

        MimeMessage mimeMessage = new MimeMessage((jakarta.mail.Session) null);
        when(mailSender.createMimeMessage()).thenReturn(mimeMessage);
        when(templateEngine.process(anyString(), any(IContext.class))).thenReturn("<html>body</html>");

        AuthoraProperties.Email emailProps = new AuthoraProperties.Email();
        emailProps.setBaseUrl("http://localhost:8080");
        emailProps.setApplicationName("TestApp");
        emailProps.setFromAddress("noreply@example.com");
        emailProps.setFromName("TestApp");
        when(properties.getEmail()).thenReturn(emailProps);

        AuthoraProperties.PasswordPolicy policy = new AuthoraProperties.PasswordPolicy();
        policy.setResetTokenExpiryMinutes(30);
        when(properties.getPasswordPolicy()).thenReturn(policy);
    }

    @Test
    @DisplayName("sendEmailVerification() processes verify-email template and sends")
    void sendEmailVerification_sendsEmail() {
        emailService.sendEmailVerification(testUser, "rawToken123");

        verify(templateEngine).process(eq("email/verify-email"), any(IContext.class));
        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    @DisplayName("sendPasswordReset() processes password-reset template and sends")
    void sendPasswordReset_sendsEmail() {
        emailService.sendPasswordReset(testUser, "resetToken456");

        verify(templateEngine).process(eq("email/password-reset"), any(IContext.class));
        verify(mailSender).send(any(MimeMessage.class));
    }

    @Test
    @DisplayName("sendPasswordChangedNotice() processes password-changed template and sends")
    void sendPasswordChangedNotice_sendsEmail() {
        emailService.sendPasswordChangedNotice(testUser);

        verify(templateEngine).process(eq("email/password-changed"), any(IContext.class));
        verify(mailSender).send(any(MimeMessage.class));
    }
}