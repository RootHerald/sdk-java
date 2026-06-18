package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 * The customer's dumb client collects an opaque evidence blob (no keys, no
 * RootHerald contact) and hands it to the customer's own server. The server uses
 * this client, authenticated with its {@code rh_sk_} secret key, to:
 * <ol>
 *   <li>mint a relay-friendly nonce — {@link #createChallenge()}</li>
 *   <li>submit the evidence for appraisal and get a verdict —
 *       {@link #attest(String, AttestOptions)}</li>
 * </ol>
 * <p>
 * This is ADDITIVE. The offline/badge-tier path
 * ({@link RootHeraldClient#verifyOffline(String)} and the Spring guard) is
 * unchanged; the optional token returned by attest with
 * {@link AttestOptions#returnToken(boolean)} is itself verifiable with it.
 * <p>
 * Uses the JDK {@link HttpClient}; no third-party HTTP dependency.
 */
public final class BackgroundCheckClient {

    /** Production RootHerald API base URL. */
    public static final String DEFAULT_BASE_URL = "https://api.rootherald.com";

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
     * {@link #attest(String, AttestOptions)} using
     * {@link Challenge#challengeId()}.
     */
    public Challenge createChallenge() {
        return createChallenge(null);
    }

    /**
     * As {@link #createChallenge()}, with an optional advisory device hint.
     */
    public Challenge createChallenge(String deviceHint) {
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
    public AttestResult attest(String evidence, AttestOptions opts) {
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

    private JsonNode post(String path, JsonNode body) {
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

        HttpResponse<String> resp;
        try {
            resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        } catch (IOException ex) {
            throw new RootHeraldException("RootHerald API unreachable: " + ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RootHeraldException("RootHerald API call interrupted", ex);
        }

        if (resp.statusCode() / 100 != 2) {
            throw mapError(resp.statusCode(), resp.body());
        }
        try {
            return mapper.readTree(resp.body());
        } catch (IOException ex) {
            throw new RootHeraldApiException(resp.statusCode(),
                    "Malformed RootHerald response: " + ex.getMessage());
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
