package io.rootherald.sample;

import io.rootherald.AttestationClaims;
import io.rootherald.client.AttestOptions;
import io.rootherald.client.AttestResult;
import io.rootherald.client.BackgroundCheckClient;
import io.rootherald.client.Challenge;
import io.rootherald.spring.RootHeraldGuard;
import io.rootherald.spring.RootHeraldGuardFilter;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Runnable Spring Boot sample showing both Root Herald paths.
 *
 * <p>Badge tier (offline verify): {@code POST /signup} with the
 * {@code X-RootHerald-Token} header set; {@code @RootHeraldGuard} verifies the
 * EAT against the JWKS before the handler runs. Configure with:
 * <pre>
 * rootherald.issuer=https://rootherald.io/myorg
 * rootherald.audience=demo-rp
 * </pre>
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

    /** Badge tier — guarded by offline JWKS verification. */
    @RestController
    public static class SignupController {
        @PostMapping("/signup")
        @RootHeraldGuard(action = "signup")
        public ResponseEntity<Map<String, Object>> signup(HttpServletRequest req) {
            AttestationClaims claims = (AttestationClaims) req.getAttribute(RootHeraldGuardFilter.CLAIMS_ATTRIBUTE);
            return ResponseEntity.ok(Map.of(
                    "status", "ok",
                    "device", claims != null ? claims.subject() : "anonymous"
            ));
        }
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
            Challenge challenge = rh.createChallenge();
            // 2) appraise the opaque evidence the client posted.
            AttestResult result = rh.attest(evidence, AttestOptions.of(challenge.challengeId()));
            if (!result.isAllowed()) {
                // An un-enrolled / failing device is a verdict, not an error.
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("ok", false, "verdict", result.verdict()));
            }
            return ResponseEntity.ok(Map.of("ok", true, "verdict", result.verdict()));
        }
    }
}
