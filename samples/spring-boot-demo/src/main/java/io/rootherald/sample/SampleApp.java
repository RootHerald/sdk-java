package io.rootherald.sample;

import io.rootherald.client.AttestOptions;
import io.rootherald.client.AttestResult;
import io.rootherald.client.BackgroundCheckClient;
import io.rootherald.client.Challenge;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Runnable Spring Boot sample showing the Root Herald Background-Check path.
 *
 * <p>Background-Check (server -&gt; server): {@code POST /attest} with the
 * dumb client's opaque evidence JSON as the body; this server appraises it with
 * the {@code rh_sk_} secret key. Set {@code ROOTHERALD_SECRET_KEY} to enable it.
 */
@SpringBootApplication
public class SampleApp {
    public static void main(String[] args) {
        SpringApplication.run(SampleApp.class, args);
    }

    /**
     * Background-Check — the dumb client POSTs its opaque evidence blob here;
     * this server appraises it with Root Herald using the rh_sk_ secret key.
     * The client never holds a key or calls Root Herald directly.
     */
    @RestController
    public static class AttestController {
        private final BackgroundCheckClient rh;

        public AttestController() {
            String secretKey = System.getenv("ROOTHERALD_SECRET_KEY");
            this.rh = secretKey == null ? null
                    : BackgroundCheckClient.builder().secretKey(secretKey).build();
        }

        @PostMapping("/attest")
        public ResponseEntity<Map<String, Object>> attest(@RequestBody String evidence) {
            if (rh == null) {
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                        .body(Map.of("error", "set ROOTHERALD_SECRET_KEY to enable /attest"));
            }
            // 1) mint a nonce; in production hand challenge.nonce() to the client
            //    first, then receive the evidence it produced. Compressed here.
            Challenge challenge = rh.issueChallenge();
            // 2) appraise the opaque evidence the client posted.
            AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.challengeId()));
            if (!result.isAllowed()) {
                // An un-enrolled / failing device is a verdict, not an error.
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("ok", false, "verdict", result.verdict()));
            }
            return ResponseEntity.ok(Map.of("ok", true, "verdict", result.verdict()));
        }
    }
}
