package dev.bermeb.authora.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class AuthException extends RuntimeException {

    private final HttpStatus status;

    public AuthException(String message) {
        this(message, HttpStatus.UNAUTHORIZED);
    }

    public AuthException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
}