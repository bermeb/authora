package dev.bermeb.authora.service;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.model.User;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.io.UnsupportedEncodingException;
import java.util.Locale;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    private final AuthoraProperties properties;

    @Async
    public void sendEmailVerification(User user, String rawToken) {
        // Build the full verification URL using the configured base URL
        String link = properties.getEmail().getBaseUrl()
                + "/api/v1/auth/email/verify?token=" + rawToken;

        Context ctx = baseContext(user);
        ctx.setVariable("verificationLink", link);
        ctx.setVariable("expiryMinutes", 60);

        sendHtml(
                user.getEmail(),
                "Verify your email - " + properties.getEmail().getApplicationName(),
                "email/verify-email",
                ctx
        );
    }

    @Async
    public void sendPasswordReset(User user, String rawToken) {
        // Build the full reset URL using the configured base URL
        String link = properties.getEmail().getBaseUrl()
                + "/api/v1/auth/password/reset?token=" + rawToken;

        Context ctx = baseContext(user);
        ctx.setVariable("resetLink", link);
        ctx.setVariable("expiryMinutes", properties.getPasswordPolicy().getResetTokenExpiryMinutes());

        sendHtml(
                user.getEmail(),
                "Password Reset - " + properties.getEmail().getApplicationName(),
                "email/password-reset",
                ctx
        );
    }

    @Async
    public void sendPasswordChangedNotice(User user) {
        Context ctx = baseContext(user);

        sendHtml(user.getEmail(),
                "Your password was changed - " + properties.getEmail().getApplicationName(),
                "email/password-changed",
                ctx
        );
    }

    private Context baseContext(User user) {
        Context ctx = new Context(Locale.ENGLISH);
        ctx.setVariable("firstName", user.getFirstName()); // personalized greeting
        ctx.setVariable("appName", properties.getEmail().getApplicationName());
        ctx.setVariable("baseUrl", properties.getEmail().getBaseUrl());
        return ctx;
    }

    private void sendHtml(String to, String subject, String templateName, Context ctx) {
        try {
            // render Thymeleaf template
            String html = templateEngine.process(templateName, ctx);

            // create a MIME message
            MimeMessage message = mailSender.createMimeMessage();
            // MimeMessageHelper simplifies the JavaMail API
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(
                    properties.getEmail().getFromAddress(),
                    properties.getEmail().getFromName()
            );
            helper.setTo(to);
            helper.setSubject(subject);
            // "true" = this is HTML
            helper.setText(html, true);

            // hand the assembled message to the mail sender (SMTP)
            mailSender.send(message);
            log.debug("Email '{}' sent to {}", subject, to);
        } catch (MessagingException | UnsupportedEncodingException e) {
            log.error("Failed to send email '{}' to {}: {}", subject, to, e.getMessage());
        }
    }
}