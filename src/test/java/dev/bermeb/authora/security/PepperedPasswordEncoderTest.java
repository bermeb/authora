package dev.bermeb.authora.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class PepperedPasswordEncoderTest {

    private static final String PEPPER = "test-pepper-value-for-unit-tests-32chars!";
    private static final int BCRYPT_STRENGTH = 4; // low cost for fast tests

    private final PepperedPasswordEncoder encoder =
            new PepperedPasswordEncoder(BCRYPT_STRENGTH, PEPPER);

    @Test
    @DisplayName("encode() returns a BCrypt hash (starts with $2a$)")
    void encode_returnsBCryptHash() {
        String hash = encoder.encode("MyPassword1!");
        assertThat(hash).startsWith("$2a$");
    }

    @Test
    @DisplayName("matches() returns true for correct password")
    void matches_correctPassword() {
        String hash = encoder.encode("MyPassword1!");
        assertThat(encoder.matches("MyPassword1!", hash)).isTrue();
    }

    @Test
    @DisplayName("matches() returns false for wrong password")
    void matches_wrongPassword() {
        String hash = encoder.encode("MyPassword1!");
        assertThat(encoder.matches("WrongPassword!", hash)).isFalse();
    }

    @Test
    @DisplayName("different pepper produces hash that does not match")
    void differentPepper_doesNotMatch() {
        String hash = encoder.encode("MyPassword1!");

        PepperedPasswordEncoder otherEncoder =
                new PepperedPasswordEncoder(BCRYPT_STRENGTH,
                        "different-pepper-also-at-least-32-bytes!");

        assertThat(otherEncoder.matches("MyPassword1!", hash)).isFalse();
    }

    @Test
    @DisplayName("constructor rejects pepper shorter than 32 bytes")
    void constructor_rejectShortPepper() {
        assertThatThrownBy(() -> new PepperedPasswordEncoder(BCRYPT_STRENGTH, "short"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    @DisplayName("constructor rejects null pepper")
    void constructor_rejectNullPepper() {
        assertThatThrownBy(() -> new PepperedPasswordEncoder(BCRYPT_STRENGTH, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}