package dev.bermeb.authora.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHashUtilTest {

    // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
    private static final String HELLO_SHA256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    @Test
    @DisplayName("hash() returns known SHA-256 hex for 'hello'")
    void hash_knownValue() {
        assertThat(TokenHashUtil.hash("hello")).isEqualTo(HELLO_SHA256);
    }

    @Test
    @DisplayName("hash() is idempotent - same input always produces same output")
    void hash_idempotent() {
        String input = "some-refresh-token-value";
        assertThat(TokenHashUtil.hash(input)).isEqualTo(TokenHashUtil.hash(input));
    }

    @Test
    @DisplayName("hash() produces different outputs for different inputs")
    void hash_differentInputs() {
        assertThat(TokenHashUtil.hash("tokenA")).isNotEqualTo(TokenHashUtil.hash("tokenB"));
    }

    @Test
    @DisplayName("hash() returns 64-character lowercase hex string")
    void hash_format() {
        String result = TokenHashUtil.hash("test-value");
        assertThat(result).hasSize(64).matches("[0-9a-f]+");
    }
}