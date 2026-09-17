package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rootherald.ActivationRefusedException;
import io.rootherald.AdmissionRefusedException;
import io.rootherald.ChallengeException;
import io.rootherald.InvalidEvidenceException;
import io.rootherald.InvalidSecretKeyException;
import io.rootherald.QuotaExceededException;
import io.rootherald.RateLimitedException;
import io.rootherald.RootHeraldApiException;
import io.rootherald.RootHeraldException;
import io.rootherald.UnknownPolicyException;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
 * Nothing the client sends locates a row. The server resolves the tenant from
 * the {@code rh_sk_} key, the challenge from the nonce the proof was made
 * over, the enrollment from the {@code enrollmentId} it minted, and the device
 * from the proof itself. No body carries a device identifier, and the
 * {@code deviceId} the backend learns at activation is never relayed to a
 * device.
 * <p>
 * Uses the JDK {@link HttpClient}; no third-party HTTP dependency.
 */
public final class RootHeraldClient {

    /** Production RootHerald API base URL. */
    public static final String DEFAULT_BASE_URL = "https://rootherald.io";

    /**
     * Per-request timeout: 30 seconds, the same in every RootHerald server SDK.
     * Applied to every request whichever {@link HttpClient} is in use.
     */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private static final String SECRET_KEY_PREFIX = "rh_sk_";

    // Server error codes that tell apart the refusals sharing one status.
    private static final String CODE_UNKNOWN_POLICY = "unknown_policy";
    private static final String CODE_QUOTA_EXCEEDED = "quota_exceeded";

    // Marks a 429 as the metered quota, whatever the body says.
    private static final String QUOTA_HEADER = "X-RootHerald-Quota";

    private final String secretKey;
    private final URI baseUri;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();

    private RootHeraldClient(Builder b) {
        this.secretKey = b.secretKey;
        this.baseUri = b.baseUri;
        this.http = b.httpClient != null ? b.httpClient
                : HttpClient.newBuilder().connectTimeout(DEFAULT_TIMEOUT).build();
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
     * {@link Challenge#nonce()}.
     * <p>
     * What the device must prove is fixed here, not at verify time. The policy
     * comes from the API key, not from this call: the key carries an identity
     * policy and, on Pro, a posture policy, and the server pins the resolved
     * policy on the challenge at mint. A {@code policy} field in a hand-built
     * body is refused with 400 {@code policy_bound_to_key}.
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
        if (opts.keyPurpose() != null) {
            body.put("keyPurpose", opts.keyPurpose());
        }
        JsonNode data = post("api/v1/attest/challenge", body);
        JsonNode nonce = data.get("nonce");
        JsonNode challenge = data.get("challenge");
        JsonNode expiresAt = data.get("expiresAt");
        if (nonce == null || challenge == null || expiresAt == null) {
            throw new RootHeraldApiException(200, "challenge response missing nonce/challenge/expiresAt");
        }
        return new Challenge(nonce.asText(), challenge.asText(), expiresAt.asText());
    }

    /**
     * POST {baseUrl}/api/v1/attest/verify — submit the opaque evidence
     * blob for server-side appraisal and return the verdict.
     * <p>
     * An un-enrolled / failing device is NOT an error — it returns a normal
     * {@link AttestResult} carrying a {@link Verdict#FAIL}/{@link Verdict#WARN}
     * verdict. Only protocol/auth/quota problems raise a
     * {@link RootHeraldApiException}; a response whose verdict token is not
     * one of the three is one too.
     *
     * @param evidence opaque blob (JSON string) from the client collector; passed through verbatim
     * @param opts     attest options carrying the challenge nonce
     */
    public AttestResult verify(String evidence, AttestOptions opts) {
        Objects.requireNonNull(evidence, "evidence");
        Objects.requireNonNull(opts, "opts");

        ObjectNode body = mapper.createObjectNode();
        body.put("nonce", opts.nonce());
        // evidence is opaque JSON; embed it verbatim as a parsed node.
        try {
            body.set("evidence", mapper.readTree(evidence));
        } catch (IOException ex) {
            throw new RootHeraldException("evidence must be valid JSON: " + ex.getMessage(), ex);
        }
        if (opts.requestedDisclosureClass() != null) {
            body.put("requestedDisclosureClass", opts.requestedDisclosureClass());
        }

        JsonNode data = post("api/v1/attest/verify", body);
        JsonNode verdictNode = data.get("verdict");
        if (verdictNode == null || !verdictNode.isObject()) {
            throw new RootHeraldApiException(200, "verify response missing verdict");
        }
        // The pass/fail token lives at verdict.device.verdict (with earStatus,
        // attestationType, quoteVerified, cohort fields, …) — NOT at the top level.
        JsonNode rawVerdict = verdictNode.path("device").path("verdict");
        String verdict = Verdict.parse(rawVerdict.isTextual() ? rawVerdict.asText() : null);
        if (verdict == null) {
            throw new RootHeraldApiException(200,
                    "verify response verdict.device.verdict is not pass/warn/fail (got " + rawVerdict + ")");
        }

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

        // `key` is a top-level sibling too, passed through as the server sent it.
        Optional<CertifiedKey> key = data.hasNonNull("key")
                ? Optional.of(parseCertifiedKey(data.get("key")))
                : Optional.empty();

        return new AttestResult(verdict, verdictNode, claims, enrollmentRequired, key);
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
     * the {@code rh_sk_} secret: every field of the record that is set is
     * sent, and nothing else is. Returns the {@link EnrollActivationChallenge}
     * to hand to the client's {@code EnrollComplete}, whose result goes to
     * {@link #relayActivate(EnrollActivationResponse)}; an iOS body enrolls
     * in this one leg and the result carries no challenge. Admission runs
     * under the identity policy bound to the API key; a device that could
     * never satisfy it is refused before it gets an AK
     * ({@link AdmissionRefusedException}). Other non-2xx statuses raise the
     * matching {@link RootHeraldApiException}.
     *
     * @param blob the client's enroll request blob
     */
    public RelayEnrollResult relayEnroll(EnrollRequestBlob blob) {
        Objects.requireNonNull(blob, "blob");

        ObjectNode body = mapper.createObjectNode();
        putIfSet(body, "ekPublicKey", blob.ekPublicKey());
        putIfSet(body, "akPublicArea", blob.akPublicArea());
        putIfSet(body, "platform", blob.platform());
        putIfSet(body, "ekCertPem", blob.ekCertPem());
        if (blob.ekCertificateChain() != null) {
            ArrayNode chain = body.putArray("ekCertificateChain");
            blob.ekCertificateChain().forEach(chain::add);
        }
        if (blob.tpmSelfReport() != null) {
            ObjectNode report = body.putObject("tpmSelfReport");
            putIfSet(report, "manufacturer", blob.tpmSelfReport().manufacturer());
            putIfSet(report, "vendorString", blob.tpmSelfReport().vendorString());
        }
        putIfSet(body, "iosKeyId", blob.iosKeyId());
        putIfSet(body, "iosAttestationObject", blob.iosAttestationObject());
        putIfSet(body, "nonce", blob.nonce());
        return relayEnroll(body);
    }

    private static void putIfSet(ObjectNode node, String field, String value) {
        if (value != null) {
            node.put(field, value);
        }
    }

    /**
     * As {@link #relayEnroll(EnrollRequestBlob)}, relaying the client's blob
     * verbatim as the JSON object it emitted: the bytes the client produced
     * are the bytes RootHerald receives, whatever fields they carry. This is
     * the path for a backend that holds the client's JSON and has no reason to
     * retype it.
     *
     * @param blobJson the client's enroll request blob, a JSON object
     */
    public RelayEnrollResult relayEnroll(String blobJson) {
        Objects.requireNonNull(blobJson, "blobJson");
        JsonNode body;
        try {
            body = mapper.readTree(blobJson);
        } catch (IOException ex) {
            throw new RootHeraldException("enroll blob must be valid JSON: " + ex.getMessage(), ex);
        }
        if (body == null || !body.isObject()) {
            throw new RootHeraldException("enroll blob must be a JSON object");
        }
        return relayEnroll((ObjectNode) body);
    }

    private RelayEnrollResult relayEnroll(ObjectNode body) {
        JsonNode data = post("api/v1/attest/enroll", body);
        if ("ios".equals(body.path("platform").asText(null)) && data.isEmpty()) {
            return RelayEnrollResult.withoutChallenge();
        }
        JsonNode enrollmentId = data.get("enrollmentId");
        if (enrollmentId == null || !enrollmentId.isTextual() || enrollmentId.asText().isEmpty()) {
            throw new RootHeraldApiException(201, "enroll response missing enrollmentId");
        }
        try {
            return RelayEnrollResult.of(new EnrollActivationChallenge(
                    enrollmentId.asText(),
                    textOrNull(data, "credentialBlob"),
                    textOrNull(data, "encryptedSecret"),
                    textOrNull(data, "challengeNonce")));
        } catch (IllegalArgumentException ex) {
            throw new RootHeraldApiException(201,
                    "enroll response missing credentialBlob/encryptedSecret or challengeNonce");
        }
    }

    /**
     * Enroll relay — leg 2. POST {baseUrl}/api/v1/attest/activate.
     * <p>
     * Relays the client's {@code EnrollComplete()} blob to RootHerald, closing
     * the enrollment that {@link #relayEnroll(EnrollRequestBlob)} opened. The
     * server finds it by {@code enrollmentId} and checks the proof against the
     * platform it recorded; an unknown, spent or foreign id and a wrong proof
     * are refused alike, with 401.
     *
     * @param activation the client's activation response; relayed verbatim
     * @return the terminal {@code {deviceId, status?, enrolledAt?}} body, for
     *         the backend only
     */
    public RelayActivateResponse relayActivate(EnrollActivationResponse activation) {
        Objects.requireNonNull(activation, "activation");

        ObjectNode body = mapper.createObjectNode();
        body.put("enrollmentId", activation.enrollmentId());
        if (activation.decryptedSecret() != null) {
            body.put("decryptedSecret", activation.decryptedSecret());
        }
        if (activation.signature() != null) {
            body.put("signature", activation.signature());
        }

        JsonNode data = post("api/v1/attest/activate", body);
        JsonNode deviceId = data.get("deviceId");
        if (deviceId == null || !deviceId.isTextual()) {
            throw new RootHeraldApiException(200, "activate response missing deviceId");
        }
        return new RelayActivateResponse(deviceId.asText(),
                textOrNull(data, "status"), textOrNull(data, "enrolledAt"));
    }

    private static String textOrNull(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.get(field).asText() : null;
    }

    /** Issue an authenticated JSON POST and map non-2xx responses to typed exceptions. */
    private JsonNode post(String path, JsonNode body) {
        HttpResponse<String> resp = rawPost(path, body);
        if (resp.statusCode() / 100 != 2) {
            throw mapError(resp);
        }
        return parseBody(resp);
    }

    /**
     * Issue an authenticated JSON POST, returning the raw response. Status
     * interpretation is left to the caller. {@code path} is relative
     * ({@code api/v1/...}) and resolves against the base URL, whose path always
     * ends in {@code /}, so a base of {@code https://host/prefix/} reaches
     * {@code https://host/prefix/api/v1/...}.
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
                .timeout(DEFAULT_TIMEOUT)
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
     * Map a non-2xx response to the matching typed exception, mirroring
     * @rootherald/node. Where one status carries two refusals the server's
     * {@code error} code (or a header) tells them apart; a code no subclass
     * covers stays the base {@link RootHeraldApiException} with the code
     * preserved.
     */
    private RootHeraldApiException mapError(HttpResponse<String> resp) {
        int status = resp.statusCode();
        JsonNode tree = tryReadTree(resp.body());
        String code = extractErrorCode(tree);
        String message = extractMessage(tree);
        RootHeraldApiException mapped = switch (status) {
            case 401 -> ActivationRefusedException.ERROR_CODE.equals(code)
                    ? new ActivationRefusedException(message)
                    : new InvalidSecretKeyException(code, message);
            case 422 -> {
                if (AdmissionRefusedException.ERROR_CODE.equals(code)) {
                    yield new AdmissionRefusedException(message);
                }
                if (code == null || CODE_UNKNOWN_POLICY.equals(code)) {
                    yield new UnknownPolicyException(code, message);
                }
                yield null;
            }
            case 409 -> new ChallengeException(code, message);
            case 400 -> new InvalidEvidenceException(code, message);
            case 429 -> CODE_QUOTA_EXCEEDED.equals(code) || resp.headers().firstValue(QUOTA_HEADER).isPresent()
                    ? new QuotaExceededException(code, message)
                    : new RateLimitedException(code, message, retryAfterSeconds(resp, tree));
            default -> null;
        };
        return mapped != null ? mapped : new RootHeraldApiException(status, code,
                message != null ? message : "RootHerald API error (HTTP " + status + ")");
    }

    /** {@code Retry-After} as whole seconds, else the body's {@code retryAfterSeconds}, else {@code null}. */
    private static Integer retryAfterSeconds(HttpResponse<String> resp, JsonNode tree) {
        Optional<String> header = resp.headers().firstValue("Retry-After");
        if (header.isPresent()) {
            try {
                return Integer.parseInt(header.get().trim());
            } catch (NumberFormatException ignored) {
                // An HTTP-date Retry-After carries no usable seconds; fall through.
            }
        }
        if (tree != null && tree.hasNonNull("retryAfterSeconds") && tree.get("retryAfterSeconds").isInt()) {
            return tree.get("retryAfterSeconds").asInt();
        }
        return null;
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
        private URI baseUri = URI.create(DEFAULT_BASE_URL + "/");
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
         * Override the production base URL. Must be an absolute https URL. A
         * path prefix is kept: requests go to {@code <baseUrl>/api/v1/...}.
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
            this.baseUri = withTrailingSlash(requireSecureBaseUri(baseUrl));
            return this;
        }

        /** Relative resolution replaces the last path segment, so the base must end in {@code /}. */
        private static URI withTrailingSlash(URI uri) {
            String text = uri.toString();
            return text.endsWith("/") ? uri : URI.create(text + "/");
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

        /**
         * Swap the underlying {@link HttpClient} (connect timeout, proxies, tests).
         * The per-request timeout stays {@link #DEFAULT_TIMEOUT}.
         */
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
