package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rootherald.ChallengeException;
import io.rootherald.InvalidEvidenceException;
import io.rootherald.InvalidSecretKeyException;
import io.rootherald.QuotaExceededException;
import io.rootherald.RootHeraldApiException;
import io.rootherald.RootHeraldException;
import io.rootherald.UnknownPolicyException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Server -&gt; server Background-Check client.
 * <p>
 * The customer's keyless client does local TPM work and hands opaque blobs to
 * the customer's own server. The server uses this client, authenticated with its
 * {@code rh_sk_} secret key, to relay those blobs to RootHerald. It mirrors the
 * four helpers of the canonical {@code @rootherald/node} backend-relay contract:
 * <ol>
 *   <li>{@link #relayEnroll(EnrollRequestBlob)} — relay the one-time device-key
 *       bootstrap ({@code POST /api/v1/devices/enroll}); resolves the asymmetric
 *       {@code 201} (fresh) / {@code 409} (already enrolled) outcomes</li>
 *   <li>{@link #relayActivate(EnrollActivationResponse)} — complete the
 *       EK&rarr;AK credential-activation handshake
 *       ({@code POST /api/v1/devices/activate})</li>
 *   <li>{@link #issueChallenge()} — mint a relay-friendly nonce
 *       ({@code POST /api/v1/attestations/challenge})</li>
 *   <li>{@link #verify(String, AttestOptions)} — submit the evidence blob for
 *       appraisal and get a verdict ({@code POST /api/v1/attestations/verify})</li>
 * </ol>
 * <p>
 * The verdict is computed by RootHerald and returned here, to the customer's
 * backend — it NEVER travels through the client, which holds no key.
 * <p>
 * This is ADDITIVE. The offline/badge-tier path
 * ({@link RootHeraldClient#verifyOffline(String)} and the Spring guard) is
 * unchanged; the optional token returned by {@link #verify(String, AttestOptions)}
 * with {@link AttestOptions#returnToken(boolean)} is itself verifiable with it.
 * <p>
 * Uses the JDK {@link HttpClient}; no third-party HTTP dependency.
 */
public final class BackgroundCheckClient {

    /** Production RootHerald API base URL. */
    public static final String DEFAULT_BASE_URL = "https://api.rootherald.io";

    private static final String SECRET_KEY_PREFIX = "rh_sk_";

    private final String secretKey;
    private final URI baseUri;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    private BackgroundCheckClient(Builder b) {
        this.secretKey = b.secretKey;
        this.baseUri = b.baseUri;
        this.http = b.httpClient != null ? b.httpClient
                : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * POST {baseUrl}/api/v1/attestations/challenge — mint a relay-friendly
     * nonce. Relay {@link Challenge#nonce()} to the client; it quotes over it,
     * then submit the resulting evidence with
     * {@link #verify(String, AttestOptions)} using
     * {@link Challenge#challengeId()}.
     */
    public Challenge issueChallenge() {
        return issueChallenge(null);
    }

    /**
     * As {@link #issueChallenge()}, with an optional advisory device hint.
     */
    public Challenge issueChallenge(String deviceHint) {
        ObjectNode body = mapper.createObjectNode();
        if (deviceHint != null) {
            body.put("deviceHint", deviceHint);
        }
        JsonNode data = post("/api/v1/attestations/challenge", body);
        JsonNode id = data.get("challengeId");
        JsonNode nonce = data.get("nonce");
        JsonNode expiresAt = data.get("expiresAt");
        if (id == null || nonce == null || expiresAt == null) {
            throw new RootHeraldApiException(200, "challenge response missing challengeId/nonce/expiresAt");
        }
        return new Challenge(id.asText(), nonce.asText(), expiresAt.asText());
    }

    /**
     * POST {baseUrl}/api/v1/attestations/verify — submit the opaque evidence
     * blob for server-side appraisal and return the verdict (plus an optional
     * signed EAT when {@link AttestOptions#returnToken(boolean)} is set).
     * <p>
     * An un-enrolled / failing device is NOT an error — it returns a normal
     * {@link AttestResult} carrying a {@code "deny"}/{@code "review"} verdict.
     * Only protocol/auth/quota problems raise a {@link RootHeraldApiException}.
     *
     * @param evidence opaque blob (JSON string) from the client collector; passed through verbatim
     * @param opts     attest options carrying the challenge id and optional policy/returnToken
     */
    public AttestResult verify(String evidence, AttestOptions opts) {
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(opts, "opts");

        ObjectNode body = mapper.createObjectNode();
        body.put("challengeId", opts.challengeId());
        // evidence is opaque JSON; embed it verbatim as a parsed node.
        try {
            body.set("evidence", mapper.readTree(evidence));
        } catch (IOException ex) {
            throw new RootHeraldException("evidence must be valid JSON: " + ex.getMessage(), ex);
        }
        if (opts.policy() != null) {
            body.put("policy", opts.policy());
        }
        if (opts.returnTokenRequested()) {
            body.put("returnToken", true);
        }

        JsonNode data = post("/api/v1/attestations/verify", body);
        JsonNode verdictNode = data.get("verdict");
        if (verdictNode == null || !verdictNode.isObject()) {
            throw new RootHeraldApiException(200, "verify response missing verdict");
        }
        String raw = verdictNode.path("verdict").asText(null);
        String token = data.hasNonNull("token") ? data.get("token").asText() : null;
        return new AttestResult(AttestResult.normalize(raw), verdictNode, token);
    }

    /**
     * Enroll relay — leg 1. POST {baseUrl}/api/v1/devices/enroll.
     * <p>
     * Relays the keyless client's {@code EnrollBegin()} blob to RootHerald with
     * the {@code rh_sk_} secret and resolves the asymmetric response:
     * <ul>
     *   <li><b>{@code 201}</b> — a fresh enroll; returns a
     *       {@link RelayEnrollResult} with {@code alreadyEnrolled() == false} and
     *       the {@link EnrollActivationChallenge}. Hand the challenge to the
     *       client's {@code EnrollComplete}, then relay the result to
     *       {@link #relayActivate(EnrollActivationResponse)}.</li>
     *   <li><b>{@code 409}</b> — the device is already enrolled; returns
     *       {@code alreadyEnrolled() == true} (no challenge). SKIP the activate
     *       leg — just use {@link RelayEnrollResult#deviceId()}.</li>
     * </ul>
     * Other non-2xx statuses raise the matching {@link RootHeraldApiException}.
     *
     * @param blob the client's enroll request blob; relayed verbatim
     */
    public RelayEnrollResult relayEnroll(EnrollRequestBlob blob) {
        Objects.requireNonNull(blob, "blob");

        ObjectNode body = mapper.createObjectNode();
        body.put("ekPublicKey", blob.ekPublicKey());
        body.put("akPublicArea", blob.akPublicArea());
        if (blob.platform() != null) {
            body.put("platform", blob.platform());
        }
        if (blob.ekCertPem() != null) {
            body.put("ekCertPem", blob.ekCertPem());
        }
        if (blob.ekCertificateChain() != null) {
            ArrayNode chain = body.putArray("ekCertificateChain");
            blob.ekCertificateChain().forEach(chain::add);
        }

        HttpResponse<String> resp = rawPost("/api/v1/devices/enroll", body);
        int status = resp.statusCode();

        // 409 = already enrolled: the body carries only `deviceId`. Resolve it and
        // signal "skip activate" instead of treating it as an error.
        if (status == 409) {
            JsonNode b = tryReadTree(resp.body());
            String deviceId = b != null && b.hasNonNull("deviceId") ? b.get("deviceId").asText() : null;
            if (deviceId == null || deviceId.isEmpty()) {
                throw new RootHeraldApiException(409, "already-enrolled (409) response missing deviceId");
            }
            return RelayEnrollResult.alreadyEnrolled(deviceId);
        }

        if (status / 100 != 2) {
            throw mapError(status, resp.body());
        }

        JsonNode data = parseBody(resp);
        JsonNode deviceId = data.get("deviceId");
        JsonNode credentialBlob = data.get("credentialBlob");
        JsonNode encryptedSecret = data.get("encryptedSecret");
        if (deviceId == null || credentialBlob == null || encryptedSecret == null) {
            throw new RootHeraldApiException(status,
                    "enroll response missing deviceId/credentialBlob/encryptedSecret");
        }
        EnrollActivationChallenge challenge = new EnrollActivationChallenge(
                deviceId.asText(), credentialBlob.asText(), encryptedSecret.asText());
        return RelayEnrollResult.fresh(deviceId.asText(), challenge);
    }

    /**
     * Enroll relay — leg 2. POST {baseUrl}/api/v1/devices/activate.
     * <p>
     * Relays the client's {@code EnrollComplete()} blob (the decrypted credential
     * secret) to RootHerald, completing the EK&rarr;AK credential-activation
     * handshake. Call this only when {@link #relayEnroll(EnrollRequestBlob)}
     * returned {@code alreadyEnrolled() == false}.
     *
     * @param activation the client's activation response; relayed verbatim
     * @return the terminal {@code {deviceId, status?, enrolledAt?}} body
     */
    public RelayActivateResponse relayActivate(EnrollActivationResponse activation) {
        Objects.requireNonNull(activation, "activation");

        ObjectNode body = mapper.createObjectNode();
        body.put("deviceId", activation.deviceId());
        body.put("decryptedSecret", activation.decryptedSecret());
        if (activation.akPublicKey() != null) {
            body.put("akPublicKey", activation.akPublicKey());
        }

        JsonNode data = post("/api/v1/devices/activate", body);
        JsonNode deviceId = data.get("deviceId");
        if (deviceId == null || !deviceId.isTextual()) {
            throw new RootHeraldApiException(200, "activate response missing deviceId");
        }
        String status = data.hasNonNull("status") ? data.get("status").asText() : null;
        String enrolledAt = data.hasNonNull("enrolledAt") ? data.get("enrolledAt").asText() : null;
        return new RelayActivateResponse(deviceId.asText(), status, enrolledAt);
    }

    /**
     * @deprecated renamed to {@link #issueChallenge()} for the ABI backend-relay
     *     contract. Retained as a thin alias for backwards compatibility.
     */
    @Deprecated
    public Challenge createChallenge() {
        return issueChallenge(null);
    }

    /**
     * @deprecated renamed to {@link #issueChallenge(String)} for the ABI
     *     backend-relay contract. Retained as a thin alias.
     */
    @Deprecated
    public Challenge createChallenge(String deviceHint) {
        return issueChallenge(deviceHint);
    }

    /**
     * @deprecated renamed to {@link #verify(String, AttestOptions)} for the ABI
     *     backend-relay contract. Retained as a thin alias.
     */
    @Deprecated
    public AttestResult attest(String evidence, AttestOptions opts) {
        return verify(evidence, opts);
    }

    /** Issue an authenticated JSON POST and map non-2xx responses to typed exceptions. */
    private JsonNode post(String path, JsonNode body) {
        HttpResponse<String> resp = rawPost(path, body);
        if (resp.statusCode() / 100 != 2) {
            throw mapError(resp.statusCode(), resp.body());
        }
        return parseBody(resp);
    }

    /**
     * Issue an authenticated JSON POST, returning the raw response. Status
     * interpretation is left to the caller — used by the enroll relay leg, which
     * must treat {@code 409} as "already enrolled" rather than an error.
     */
    private HttpResponse<String> rawPost(String path, JsonNode body) {
        URI endpoint = baseUri.resolve(path);
        String payload;
        try {
            payload = mapper.writeValueAsString(body);
        } catch (Exception ex) {
            throw new RootHeraldException("Failed to serialise request: " + ex.getMessage(), ex);
        }

        HttpRequest req = HttpRequest.newBuilder(endpoint)
                .header("Authorization", "Bearer " + secretKey)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        try {
            return http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException ex) {
            throw new RootHeraldException("RootHerald API unreachable: " + ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RootHeraldException("RootHerald API call interrupted", ex);
        }
    }

    /** Parse a 2xx response body, mapping a parse failure to a typed API error. */
    private JsonNode parseBody(HttpResponse<String> resp) {
        try {
            return mapper.readTree(resp.body());
        } catch (IOException ex) {
            throw new RootHeraldApiException(resp.statusCode(),
                    "Malformed RootHerald response: " + ex.getMessage());
        }
    }

    /** Parse a body unknown-safely, returning {@code null} on any failure. */
    private JsonNode tryReadTree(String body) {
        try {
            return mapper.readTree(body);
        } catch (IOException ex) {
            return null;
        }
    }

    /** Map a non-2xx status to the matching typed exception, mirroring @rootherald/node. */
    private RootHeraldApiException mapError(int status, String body) {
        String message = extractMessage(body);
        return switch (status) {
            case 401 -> new InvalidSecretKeyException(message);
            case 422 -> new UnknownPolicyException(message);
            case 409 -> new ChallengeException(message);
            case 400 -> new InvalidEvidenceException(message);
            case 429 -> new QuotaExceededException(message);
            default -> new RootHeraldApiException(status,
                    message != null ? message : "RootHerald API error (HTTP " + status + ")");
        };
    }

    private String extractMessage(String body) {
        try {
            JsonNode tree = mapper.readTree(body);
            if (tree.hasNonNull("message")) {
                return tree.get("message").asText();
            }
            if (tree.hasNonNull("error_description")) {
                return tree.get("error_description").asText();
            }
        } catch (IOException ignored) {
            // non-JSON body — fall through
        }
        return null;
    }

    /** Builder for {@link BackgroundCheckClient}. */
    public static final class Builder {
        private String secretKey;
        private URI baseUri = URI.create(DEFAULT_BASE_URL);
        private HttpClient httpClient;

        /**
         * Your RootHerald secret key (rh_sk_…). Required. A publishable key
         * (rh_pk_…) is rejected — it must never be used server-side.
         */
        public Builder secretKey(String secretKey) {
            if (secretKey == null || secretKey.isEmpty()) {
                throw new IllegalArgumentException("a secret key (rh_sk_…) is required");
            }
            if (!secretKey.startsWith(SECRET_KEY_PREFIX)) {
                throw new IllegalArgumentException(
                        "secretKey must be a secret key (rh_sk_…); a publishable key (rh_pk_…) must never be used server-side");
            }
            this.secretKey = secretKey;
            return this;
        }

        /** Override the production base URL. */
        public Builder baseUrl(String baseUrl) {
            this.baseUri = URI.create(baseUrl);
            return this;
        }

        /** Swap the underlying {@link HttpClient} (timeouts, proxies, tests). */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public BackgroundCheckClient build() {
            if (secretKey == null) {
                throw new IllegalArgumentException("secretKey is required");
            }
            return new BackgroundCheckClient(this);
        }
    }
}
