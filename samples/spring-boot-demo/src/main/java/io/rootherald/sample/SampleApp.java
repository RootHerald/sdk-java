package io.rootherald.sample;

import io.rootherald.client.AttestOptions;
import io.rootherald.client.AttestResult;
import io.rootherald.client.CertifiedKey;
import io.rootherald.client.Challenge;
import io.rootherald.client.ChallengeOptions;
import io.rootherald.client.KeyChallenge;
import io.rootherald.client.KeyChallengeOptions;
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
 * Runnable Spring Boot sample of the Root Herald server -&gt; server flow:
 * attest a device, mint a signing key on it, check its signatures locally.
 *
 * <p>Set {@code ROOTHERALD_SECRET_KEY} and the routes come alive:
 * <ol>
 *   <li>{@code POST /challenge} — mint a challenge asking for identity and
 *       posture; relay {@code challenge} to the client</li>
 *   <li>{@code POST /attest} — appraise the client's evidence; answers the
 *       device's alias on a pass</li>
 *   <li>{@code POST /key-challenge} — mint a key challenge for that device;
 *       relay {@code keyChallenge} to the client</li>
 *   <li>{@code POST /certify} — register the key the client minted; keep its JWK</li>
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
                    .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_POSTURE));
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
            return ResponseEntity.ok(Map.of("ok", true, "verdict", result.verdict(),
                    "deviceId", result.deviceId().orElse("")));
        }

        /**
         * 3) Mint a key challenge for the device that just passed; hand
         * {@code keyChallenge} to the client, whose MintKey answers with a
         * certification.
         */
        @PostMapping("/key-challenge")
        public ResponseEntity<?> keyChallenge(@RequestBody KeyChallengeBody body) {
            if (rh == null) {
                return notConfigured();
            }
            KeyChallenge challenge = rh.issueKeyChallenge(KeyChallengeOptions.of(KeyChallengeOptions.PURPOSE_SIGN)
                    .expectedDevices(body.deviceId()));
            return ResponseEntity.ok(challenge);
        }

        /** 4) Register the key the client minted; keep its public half. */
        @PostMapping("/certify")
        public ResponseEntity<Map<String, Object>> certify(@RequestBody CertifyBody body) {
            if (rh == null) {
                return notConfigured();
            }
            CertifiedKey key = rh.certifyKey(body.nonce(), body.certification());
            keys.put(key.keyId(), key);
            return ResponseEntity.ok(Map.of("keyId", key.keyId(), "deviceId", key.deviceId(),
                    "alg", key.alg()));
        }

        /**
         * 5) Later, the device signs something with its key. Check it against
         * the JWK from the certification; no Root Herald call.
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

    /** {@code deviceId} is the alias {@code /attest} answered. */
    public record KeyChallengeBody(String deviceId) {
    }

    /** {@code nonce} is the handle from the key challenge; {@code certification} is the client's JSON, passed through verbatim. */
    public record CertifyBody(String nonce, String certification) {
    }

    /** {@code message} and {@code signature} are base64. */
    public record SignatureBody(String keyId, String message, String signature) {
    }
}
