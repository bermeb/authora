package dev.bermeb.authora.util;

import dev.bermeb.authora.config.AuthoraProperties;
import dev.bermeb.authora.exception.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
public class PasswordPolicyValidator {

    private final AuthoraProperties properties;

    public void validate(String password) {
       List<String> violations = new ArrayList<>();
       AuthoraProperties.PasswordPolicy policy = properties.getPasswordPolicy();

       if(password == null || password.length() < policy.getMinLength()) {
           violations.add("at least " + policy.getMinLength() + " characters");
           return;
       }

       if (policy.isRequireUppercase() && password.chars().noneMatch(Character::isUpperCase)) {
           violations.add("one uppercase letter");
       }

       if(policy.isRequireLowercase() && password.chars().noneMatch(Character::isLowerCase)) {
           violations.add("one lowercase letter");
       }

       if(policy.isRequireNumbers() && password.chars().noneMatch(Character::isDigit)) {
           violations.add("one number");
       }

       if (policy.isRequireSpecialCharacters() &&
               // TODO: Replace with property of allowed characters
               password.chars().noneMatch(c -> "!@#$%^&*()_+-=[]{}|;':\",./<>?".indexOf(c) >= 0)) {
           violations.add("one special character");
       }

       if(!violations.isEmpty()) {
           throw new AuthException("Password must contain: " + String.join(", ", violations));
       }
    }
}