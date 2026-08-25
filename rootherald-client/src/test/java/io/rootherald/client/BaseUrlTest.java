package io.rootherald.client;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * The secret rides in an Authorization header on every request and is
 * full-privilege, so a base URL that is not https hands it to anyone on the path.
 * A typo is enough, and nothing downstream notices because the request itself
 * still succeeds.
 */
class BaseUrlTest {

    private static BackgroundCheckClient.Builder builder() {
        return BackgroundCheckClient.builder().secretKey("rh_sk_test_xxx");
    }

    @Test
    void rejectsPlainHttp() {
        assertThrows(IllegalArgumentException.class,
                () -> builder().baseUrl("http://api.example.test"));
        assertThrows(IllegalArgumentException.class,
                () -> builder().baseUrl("http://rootherald.io"));
    }

    @Test
    void rejectsUrlWithoutAnAbsoluteScheme() {
        assertThrows(IllegalArgumentException.class,
                () -> builder().baseUrl("api.example.test"));
        assertThrows(IllegalArgumentException.class,
                () -> builder().baseUrl("//api.example.test"));
        assertThrows(IllegalArgumentException.class,
                () -> builder().baseUrl(""));
        assertThrows(IllegalArgumentException.class,
                () -> builder().baseUrl(null));
    }

    /** Loopback stays usable so the local docker stack works over http. */
    @Test
    void acceptsHttpsAndLoopback() {
        assertDoesNotThrow(() -> builder().baseUrl("https://api.example.test"));
        assertDoesNotThrow(() -> builder().baseUrl("http://localhost:8080"));
        assertDoesNotThrow(() -> builder().baseUrl("http://127.0.0.1:5000"));
    }
}
