package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rootherald.AdmissionRefusedException;
import io.rootherald.ChallengeException;
import io.rootherald.InvalidEvidenceException;
import io.rootherald.InvalidSecretKeyException;
import io.rootherald.PolicyDowngradeException;
import io.rootherald.QuotaExceededException;
import io.rootherald.RootHeraldApiException;
import io.rootherald.RootHeraldException;
import io.rootherald.UnknownPolicyException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Server -&gt; server Background-Check client.
 * <p>
 * The customer's keyless client does local TPM work and hands opaque blobs to
 * the customer's own server. The server uses this client, authenticated with its
 * {@code rh_sk_} secret key, to relay those blobs to RootHerald. It mirrors the
 * four helpers of the canonical {@code @rootherald/node} backend-relay contract:
 * <ol>
 *   <li>{@link #relayEnroll(EnrollRequestBlob)} — relay the one-time device-key
 *       bootstrap ({@code POST /api/v1/attest/enroll}); resolves the asymmetric
 *       enroll challenge</li>
 *   <li>{@link #relayActivate(EnrollActivationResponse)} — complete the
 *       EK&rarr;AK credential-activation handshake
 *       ({@code POST /api/v1/attest/activate})</li>
 *   <li>{@link #issueChallenge(ChallengeOptions)} — mint a challenge carrying
 *       the ask ({@code POST /api/v1/attest/challenge})</li>
 *   <li>{@link #verify(String, AttestOptions)} — submit the evidence blob for
 *       appraisal and get a verdict ({@code POST /api/v1/attest/verify})</li>
 * </ol>
 * <p>
 * The verdict is computed by RootHerald and returned here, to the customer's
 * backend — it NEVER travels through the client, which holds no key.
 * <p>
 * Uses the JDK {@link HttpClient}; no third-party HTTP dependency.
 */
public final class RootHeraldClient {

    /** Production RootHerald API base URL. */
    public static final String DEFAULT_BASE_URL = "https://rootherald.io";

    private static final String SECRET_KEY_PREFIX = "rh_sk_";

    private final String secretKey;
    private final URI baseUri;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    private RootHeraldClient(Builder b) {
        this.secretKey = b.secretKey;
        this.baseUri = b.baseUri;
        this.http = b.httpClient != null ? b.httpClient
                : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * POST {baseUrl}/api/v1/attest/challenge with the server default ask
     * (identity + posture). See {@link #issueChallenge(ChallengeOptions)}.
     */
    public Challenge issueChallenge() {
        return issueChallenge(ChallengeOptions.defaults());
    }

    /**
     * As {@link #issueChallenge()}, with an optional advisory device hint.
     */
    public Challenge issueChallenge(String deviceHint) {
        return issueChallenge(ChallengeOptions.defaults().deviceHint(deviceHint));
    }

    /**
     * POST {baseUrl}/api/v1/attest/challenge — mint a challenge that carries
     * the ask. Relay {@link Challenge#challenge()} to the client verbatim; it
     * quotes over it, then submit the resulting evidence with
     * {@link #verify(String, AttestOptions)} using
     * {@link Challenge#challengeId()}.
     * <p>
     * What the device must prove is fixed here, not at verify time: a policy
     * named on the challenge is stored with it, and verify may only tighten it.
     */
    public Challenge issueChallenge(ChallengeOptions opts) {
        Objects.requireNonNull(opts, "opts");
        ObjectNode body = mapper.createObjectNode();
        if (opts.deviceHint() != null) {
            body.put("deviceHint", opts.deviceHint());
        }
        if (opts.ask() != null && !opts.ask().isEmpty()) {
            ArrayNode ask = body.putArray("ask");
            opts.ask().forEach(ask::add);
        }
        if (opts.policy() != null) {
            body.put("policy", opts.policy());
        }
        if (opts.keyPurpose() != null) {
            body.put("keyPurpose", opts.keyPurpose());
        }
        JsonNode data = post("/api/v1/attest/challenge", body);
        JsonNode id = data.get("challengeId");
        JsonNode nonce = data.get("nonce");
        JsonNode expiresAt = data.get("expiresAt");
        if (id == null || nonce == null || expiresAt == null) {
            throw new RootHeraldApiException(200, "challenge response missing challengeId/nonce/expiresAt");
        }
        String challenge = data.hasNonNull("challenge") ? data.get("challenge").asText() : null;
        return new Challenge(id.asText(), challenge, nonce.asText(), expiresAt.asText());
    }

    /**
     * POST {baseUrl}/api/v1/attest/verify — submit the opaque evidence
     * blob for server-side appraisal and return the verdict.
     * <p>
     * An un-enrolled / failing device is NOT an error — it returns a normal
     * {@link AttestResult} carrying a {@code "deny"}/{@code "review"} verdict.
     * Only protocol/auth/quota problems raise a {@link RootHeraldApiException}.
     *
     * @param evidence opaque blob (JSON string) from the client collector; passed through verbatim
     * @param opts     attest options carrying the challenge id and optional policy
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
        if (opts.requestedDisclosureClass() != null) {
            body.put("requestedDisclosureClass", opts.requestedDisclosureClass());
        }

        JsonNode data = post("/api/v1/attest/verify", body);
        JsonNode verdictNode = data.get("verdict");
        if (verdictNode == null || !verdictNode.isObject()) {
            throw new RootHeraldApiException(200, "verify response missing verdict");
        }
        // The pass/fail token lives at verdict.device.verdict (with earStatus,
        // attestationType, quoteVerified, cohort fields, …) — NOT at the top level.
        String raw = verdictNode.path("device").path("verdict").asText(null);

        // assuranceClaimsMet + enrollmentRequired are top-level siblings of
        // `verdict`, mirroring @rootherald/node — not part of the verdict node.
        List<String> claims = new ArrayList<>();
        JsonNode claimsNode = data.get("assuranceClaimsMet");
        if (claimsNode != null && claimsNode.isArray()) {
            claimsNode.forEach(c -> {
                if (c.isTextual()) {
                    claims.add(c.asText());
                }
            });
        }
        boolean enrollmentRequired = data.path("enrollmentRequired").asBoolean(false);

        // `key` is a top-level sibling too, present only on a passing verdict
        // for a challenge that asked for a key.
        Optional<CertifiedKey> key = data.hasNonNull("key")
                ? Optional.of(parseCertifiedKey(data.get("key")))
                : Optional.empty();

        return new AttestResult(AttestResult.normalize(raw), verdictNode, claims, enrollmentRequired, key);
    }

    private CertifiedKey parseCertifiedKey(JsonNode node) {
        JsonNode jwk = node.get("jwk");
        if (!node.hasNonNull("keyId") || !node.hasNonNull("certifiedAt")
                || jwk == null || !jwk.isObject()
                || !jwk.hasNonNull("kty") || !jwk.hasNonNull("crv")
                || !jwk.hasNonNull("x") || !jwk.hasNonNull("y")) {
            throw new RootHeraldApiException(200, "verify response key missing keyId/jwk/certifiedAt");
        }
        Instant certifiedAt;
        try {
            certifiedAt = Instant.parse(node.get("certifiedAt").asText());
        } catch (DateTimeParseException ex) {
            throw new RootHeraldApiException(200, "verify response key.certifiedAt is not an instant");
        }
        return new CertifiedKey(
                node.get("keyId").asText(),
                new Jwk(jwk.get("kty").asText(), jwk.get("crv").asText(),
                        jwk.get("x").asText(), jwk.get("y").asText()),
                node.hasNonNull("purpose") ? node.get("purpose").asText() : null,
                node.hasNonNull("authPolicy") ? node.get("authPolicy").asText() : null,
                certifiedAt);
    }

    /**
     * Enroll relay — leg 1. POST {baseUrl}/api/v1/attest/enroll.
     * <p>
     * Relays the keyless client's {@code EnrollBegin()} blob to RootHerald with
     * the {@code rh_sk_} secret and resolves the asymmetric response:
     * <p>Returns the {@link EnrollActivationChallenge} to hand to the client's
     * {@code EnrollComplete}, whose result goes to
     * {@link #relayActivate(EnrollActivationResponse)}. Non-2xx statuses raise
     * the matching {@link RootHeraldApiException}.
     *
     * @param blob the client's enroll request blob; relayed verbatim
     */
    public RelayEnrollResult relayEnroll(EnrollRequestBlob blob) {
        return relayEnroll(blob, null);
    }

    /**
     * As {@link #relayEnroll(EnrollRequestBlob)}, admitted against a live
     * challenge: the server runs admission against the policy stored on that
     * challenge instead of the tenant default, so a device that could never
     * satisfy it is refused before it gets an AK
     * ({@link AdmissionRefusedException}).
     *
     * @param challengeId a challenge id from {@link #issueChallenge(ChallengeOptions)},
     *                    sent as the {@code challengeId} query parameter; {@code null} to omit
     */
    public RelayEnrollResult relayEnroll(EnrollRequestBlob blob, String challengeId) {
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

        String path = "/api/v1/attest/enroll";
        if (challengeId != null && !challengeId.isEmpty()) {
            path += "?challengeId=" + URLEncoder.encode(challengeId, StandardCharsets.UTF_8);
        }
        HttpResponse<String> resp = rawPost(path, body);
        int status = resp.statusCode();

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
        String echoedChallengeId = data.hasNonNull("challengeId") ? data.get("challengeId").asText() : null;
        return RelayEnrollResult.fresh(deviceId.asText(), challenge, echoedChallengeId);
    }

    /**
     * Enroll relay — leg 2. POST {baseUrl}/api/v1/attest/activate.
     * <p>
     * Relays the client's {@code EnrollComplete()} blob (the decrypted credential
     * secret) to RootHerald, completing the EK&rarr;AK credential-activation
     * handshake. Call this only when {@link #relayEnroll(EnrollRequestBlob)}
     * challenge.
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

        JsonNode data = post("/api/v1/attest/activate", body);
        JsonNode deviceId = data.get("deviceId");
        if (deviceId == null || !deviceId.isTextual()) {
            throw new RootHeraldApiException(200, "activate response missing deviceId");
        }
        String status = data.hasNonNull("status") ? data.get("status").asText() : null;
        String enrolledAt = data.hasNonNull("enrolledAt") ? data.get("enrolledAt").asText() : null;
        return new RelayActivateResponse(deviceId.asText(), status, enrolledAt);
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
     * interpretation is left to the caller. {@code path} may carry a query string.
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
        if (body == null) {
            return null;
        }
        try {
            return mapper.readTree(body);
        } catch (IOException | RuntimeException ex) {
            return null;
        }
    }

    /**
     * Map a non-2xx status to the matching typed exception, mirroring
     * @rootherald/node. A 422 is split on the server's {@code error} code:
     * {@code policy_downgrade} and {@code admission_refused} get their own
     * types; anything else is the policy-resolution failure.
     */
    private RootHeraldApiException mapError(int status, String body) {
        JsonNode tree = tryReadTree(body);
        String code = extractErrorCode(tree);
        String message = extractMessage(tree);
        return switch (status) {
            case 401 -> new InvalidSecretKeyException(code, message);
            case 422 -> {
                if (PolicyDowngradeException.ERROR_CODE.equals(code)) {
                    yield new PolicyDowngradeException(message);
                }
                if (AdmissionRefusedException.ERROR_CODE.equals(code)) {
                    yield new AdmissionRefusedException(message);
                }
                yield new UnknownPolicyException(code, message);
            }
            case 409 -> new ChallengeException(code, message);
            case 400 -> new InvalidEvidenceException(code, message);
            case 429 -> new QuotaExceededException(code, message);
            default -> new RootHeraldApiException(status, code,
                    message != null ? message : "RootHerald API error (HTTP " + status + ")");
        };
    }

    /** The server's {@code error} discriminator ({@code code} accepted too), or {@code null}. */
    private static String extractErrorCode(JsonNode tree) {
        if (tree == null) {
            return null;
        }
        if (tree.hasNonNull("error") && tree.get("error").isTextual()) {
            return tree.get("error").asText();
        }
        if (tree.hasNonNull("code") && tree.get("code").isTextual()) {
            return tree.get("code").asText();
        }
        return null;
    }

    private static String extractMessage(JsonNode tree) {
        if (tree == null) {
            return null;
        }
        for (String field : new String[] {"message", "detail", "error_description"}) {
            if (tree.hasNonNull(field) && tree.get(field).isTextual()) {
                return tree.get(field).asText();
            }
        }
        return null;
    }

    /** Builder for {@link RootHeraldClient}. */
    public static final class Builder {
        private String secretKey;
        private URI baseUri = URI.create(DEFAULT_BASE_URL);
        private HttpClient httpClient;

        /**
         * Your RootHerald secret key (rh_sk_…). Required. Used server-side as a
         * Bearer token; any value not starting with rh_sk_ is rejected.
         */
        public Builder secretKey(String secretKey) {
            if (secretKey == null || secretKey.isEmpty()) {
                throw new IllegalArgumentException("a secret key (rh_sk_…) is required");
            }
            if (!secretKey.startsWith(SECRET_KEY_PREFIX)) {
                throw new IllegalArgumentException(
                        "RootHerald secret key must start with rh_sk_");
            }
            this.secretKey = secretKey;
            return this;
        }

        /**
         * Override the production base URL. Must be an absolute https URL.
         *
         * <p>The secret rides in an Authorization header on every request and is
         * full-privilege, so an {@code http://} or scheme-less base URL hands it
         * to anyone on the path. A typo is enough, and nothing downstream notices
         * because the request itself still succeeds. Loopback is excepted so the
         * local docker stack keeps working over http.
         *
         * @throws IllegalArgumentException when the URL is not absolute https or loopback
         */
        public Builder baseUrl(String baseUrl) {
            this.baseUri = requireSecureBaseUri(baseUrl);
            return this;
        }

        private static URI requireSecureBaseUri(String baseUrl) {
            URI uri;
            try {
                uri = URI.create(baseUrl == null ? "" : baseUrl);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException(
                        "baseUrl must be an absolute https URL (got '" + baseUrl + "')", e);
            }
            if (uri.getScheme() == null || uri.getHost() == null) {
                throw new IllegalArgumentException(
                        "baseUrl must be an absolute https URL (got '" + baseUrl + "')");
            }
            if ("https".equalsIgnoreCase(uri.getScheme()) || isLoopbackHost(uri.getHost())) {
                return uri;
            }
            throw new IllegalArgumentException(
                    "baseUrl must use https (got '" + baseUrl + "')");
        }

        private static boolean isLoopbackHost(String host) {
            String stripped = host.replace("[", "").replace("]", "");
            if ("localhost".equalsIgnoreCase(stripped)) {
                return true;
            }
            try {
                return InetAddress.getByName(stripped).isLoopbackAddress();
            } catch (UnknownHostException e) {
                return false;
            }
        }

        /** Swap the underlying {@link HttpClient} (timeouts, proxies, tests). */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public RootHeraldClient build() {
            if (secretKey == null) {
                throw new IllegalArgumentException("secretKey is required");
            }
            return new RootHeraldClient(this);
        }
    }
}
