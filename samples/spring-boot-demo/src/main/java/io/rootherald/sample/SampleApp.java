package io.rootherald.sample;

import io.rootherald.client.AttestOptions;
import io.rootherald.client.AttestResult;
import io.rootherald.client.CertifiedKey;
import io.rootherald.client.Challenge;
import io.rootherald.client.ChallengeOptions;
import io.rootherald.client.KeySignatures;
import io.rootherald.client.RootHeraldClient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Runnable Spring Boot sample of the Root Herald server -&gt; server flow with
 * a certified device key.
 *
 * <p>Set {@code ROOTHERALD_SECRET_KEY} and the three routes come alive:
 * <ol>
 *   <li>{@code POST /challenge} — mint a challenge asking for identity,
 *       posture and a signing key; relay {@code challenge} to the client</li>
 *   <li>{@code POST /attest} — appraise the client's evidence; on a pass,
 *       keep the certified key</li>
 *   <li>{@code POST /verify-signature} — check a later signature from the
 *       device against the stored key, locally, with no Root Herald call</li>
 * </ol>
 */
@SpringBootApplication
public class SampleApp {
    public static void main(String[] args) {
        SpringApplication.run(SampleApp.class, args);
    }

    @RestController
    public static class AttestController {
        private final RootHeraldClient rh;
        /** Certified keys by keyId. A real backend stores these against the user. */
        private final Map<String, CertifiedKey> keys = new ConcurrentHashMap<>();

        public AttestController() {
            // A plain object; in a real app register it once as a @Bean.
            String secretKey = System.getenv("ROOTHERALD_SECRET_KEY");
            this.rh = secretKey == null ? null
                    : RootHeraldClient.builder().secretKey(secretKey).build();
        }

        /** 1) Mint a challenge that carries the ask; hand {@code challenge} to the client. */
        @PostMapping("/challenge")
        public ResponseEntity<?> challenge() {
            if (rh == null) {
                return notConfigured();
            }
            Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
                    .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_POSTURE, ChallengeOptions.ASK_KEY)
                    .keyPurpose(ChallengeOptions.KEY_PURPOSE_SIGN));
            return ResponseEntity.ok(challenge);
        }

        /**
         * 2) The client quoted over the challenge and posts its opaque evidence
         * here with the challenge nonce; appraise it with the rh_sk_ secret key.
         */
        @PostMapping("/attest")
        public ResponseEntity<Map<String, Object>> attest(@RequestBody AttestBody body) {
            if (rh == null) {
                return notConfigured();
            }
            AttestResult result = rh.verify(body.evidence(), AttestOptions.of(body.nonce()));
            if (!result.isPass()) {
                // An un-enrolled / failing device is a verdict, not an error.
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("ok", false, "verdict", result.verdict(),
                                "enrollmentRequired", result.enrollmentRequired()));
            }
            // The key is present only on a pass for a challenge that asked for one.
            result.key().ifPresent(k -> keys.put(k.keyId(), k));
            return ResponseEntity.ok(Map.of("ok", true, "verdict", result.verdict(),
                    "keyId", result.key().map(CertifiedKey::keyId).orElse("")));
        }

        /**
         * 3) Later, the device signs something with its TPM-resident key. Check
         * it against the JWK from the attestation; no Root Herald call.
         */
        @PostMapping("/verify-signature")
        public ResponseEntity<Map<String, Object>> verifySignature(@RequestBody SignatureBody body) {
            CertifiedKey key = keys.get(body.keyId());
            if (key == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "unknown keyId"));
            }
            boolean valid = KeySignatures.verifyKeySignature(key.jwk(),
                    Base64.getDecoder().decode(body.message()),
                    Base64.getDecoder().decode(body.signature()));
            return ResponseEntity.status(valid ? HttpStatus.OK : HttpStatus.FORBIDDEN)
                    .body(Map.of("valid", valid));
        }

        private static ResponseEntity<Map<String, Object>> notConfigured() {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED)
                    .body(Map.of("error", "set ROOTHERALD_SECRET_KEY to enable this route"));
        }
    }

    /** {@code nonce} is the handle from the challenge; {@code evidence} is the client's opaque JSON, passed through verbatim. */
    public record AttestBody(String nonce, String evidence) {
    }

    /** {@code message} and {@code signature} are base64. */
    public record SignatureBody(String keyId, String message, String signature) {
    }
}
