package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.rootherald.ActivationRefusedException;
import io.rootherald.AdmissionRefusedException;
import io.rootherald.ChallengeException;
import io.rootherald.ExpectedNotEnforcedException;
import io.rootherald.InvalidAskException;
import io.rootherald.InvalidEvidenceException;
import io.rootherald.InvalidSecretKeyException;
import io.rootherald.QuotaExceededException;
import io.rootherald.RateLimitedException;
import io.rootherald.RefusingBudget;
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
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Server -&gt; server Background-Check client.
 * <p>
 * The customer's keyless client does local TPM work and hands opaque blobs to
 * the customer's own server. The server uses this client, authenticated with its
 * {@code rh_sk_} secret key, to drive three ceremonies of two legs each, the
 * same six helpers as {@code @rootherald/node}:
 * <ul>
 *   <li>enroll — {@link #relayEnroll(EnrollRequestBlob)} /
 *       {@link #relayActivate(EnrollActivationResponse)}: the installation's
 *       attestation key is bound to its endorsement key
 *       ({@code POST /api/v1/attest/enroll}, {@code /activate})</li>
 *   <li>mint a key — {@link #issueKeyChallenge(KeyChallengeOptions)} /
 *       {@link #certifyKey(String, String)}: the AK certifies a new sign or
 *       decrypt key ({@code POST /api/v1/keys/challenge}, {@code /certify})</li>
 *   <li>attest — {@link #issueChallenge(ChallengeOptions)} /
 *       {@link #verify(String, AttestOptions)}: the AK quotes what the
 *       challenge asked ({@code POST /api/v1/attest/challenge}, {@code /verify})</li>
 * </ul>
 * <p>
 * The verdict is computed by RootHerald and returned here, to the customer's
 * backend — it NEVER travels through the client, which holds no RootHerald key.
 * <p>
 * Nothing the client sends locates a row. The server resolves the tenant from
 * the {@code rh_sk_} key, the challenge from the nonce the proof was made
 * over, the enrollment from the {@code enrollmentId} it minted, and the
 * installation from the proof itself. No body carries a device identifier, and
 * the {@code deviceId} the backend learns at activation is never relayed to a
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
    private static final String CODE_KEY_ROTATION_CONFLICT = "key_rotation_conflict";

    // Marks a 429 as the budget, whatever the body says.
    private static final String QUOTA_HEADER = "X-RootHerald-Quota";

    private static final Set<String> KEY_FORMATS = Set.of("jwe", "apple-ecies");
    private static final Set<String> EC_ALGS = Set.of("ES256", "ECDH-ES");
    private static final Set<String> RSA_ALGS = Set.of("RS256", "RSA-OAEP-256");

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

    // ── Ceremony 3: attest ────────────────────────────────────────────────

    /**
     * POST {baseUrl}/api/v1/attest/challenge with the server default ask
     * (identity + posture), from any device. See {@link #issueChallenge(ChallengeOptions)}.
     */
    public Challenge issueChallenge() {
        return issueChallenge(ChallengeOptions.defaults());
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
     * <p>
     * {@link ChallengeOptions#expectedKey(String)} and
     * {@link ChallengeOptions#expectedDevices(String...)} are resolved here and
     * enforced after the proof verifies; pass the same values to
     * {@link AttestOptions}, which checks the verdict echoed them.
     */
    public Challenge issueChallenge(ChallengeOptions opts) {
        Objects.requireNonNull(opts, "opts");
        ObjectNode body = mapper.createObjectNode();
        if (opts.ask() != null && !opts.ask().isEmpty()) {
            ArrayNode ask = body.putArray("ask");
            opts.ask().forEach(ask::add);
        }
        putIfSet(body, "expectedKey", opts.expectedKey());
        putAliases(body, opts.expectedDevices());
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
     * verdict. Only protocol/auth/budget problems raise a
     * {@link RootHeraldApiException}; a response whose verdict token is not
     * one of the three is one too.
     * <p>
     * When the challenge named {@code expectedKey} or {@code expectedDevices},
     * pass the same values here: the verdict must echo them under
     * {@code expected}, and a response that does not is refused with
     * {@link ExpectedNotEnforcedException}.
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

        AttestResult result = new AttestResult(verdict, verdictNode, claims, enrollmentRequired);
        if (opts.expectedKey() != null || opts.expectedDevices() != null) {
            requireExpectedEnforced(result, opts.expectedKey(), opts.expectedDevices());
        }
        return result;
    }

    /**
     * A verdict is only as bound as the server says it enforced. The API
     * ignores unknown JSON fields, so a server that predates the binding would
     * accept any device and answer a verdict with no {@code expected} block;
     * comparing the echo with what was asked turns that silence into a refusal.
     */
    private static void requireExpectedEnforced(AttestResult result, String expectedKey,
                                                List<String> expectedDevices) {
        ExpectedBinding echoed = result.expected().orElse(null);
        if (expectedKey != null && (echoed == null || !expectedKey.equals(echoed.key()))) {
            throw new ExpectedNotEnforcedException(
                    "verify response did not echo the expectedKey the challenge named; the binding was not enforced");
        }
        if (expectedDevices != null) {
            if (echoed == null || echoed.devices() == null
                    || !new HashSet<>(echoed.devices()).equals(new HashSet<>(expectedDevices))) {
                throw new ExpectedNotEnforcedException(
                        "verify response did not echo the expectedDevices the challenge named; the binding was not enforced");
            }
            Optional<String> ueid = result.deviceId();
            if (!Verdict.FAIL.equals(result.verdict()) && ueid.isPresent()
                    && !expectedDevices.contains(ueid.get())) {
                throw new ExpectedNotEnforcedException(
                        "verify response names a device outside expectedDevices; the binding was not enforced");
            }
        }
    }

    // ── Ceremony 2: mint a key ────────────────────────────────────────────

    /** POST {baseUrl}/api/v1/keys/challenge for a purpose, from any device. */
    public KeyChallenge issueKeyChallenge(String purpose) {
        return issueKeyChallenge(KeyChallengeOptions.of(purpose));
    }

    /**
     * POST {baseUrl}/api/v1/keys/challenge — mint a single-use key challenge
     * for a purpose. Relay {@link KeyChallenge#keyChallenge()} to the client
     * verbatim; its {@code MintKey} answers with a certification, which you
     * submit with {@link #certifyKey(String, String)} under
     * {@link KeyChallenge#nonce()}.
     * <p>
     * Refused with {@code 422 key_disclosure_too_low} when the API key's
     * disclosure ceiling is below {@code pseudonymous}: a key whose id could
     * never be returned is never minted.
     */
    public KeyChallenge issueKeyChallenge(KeyChallengeOptions opts) {
        Objects.requireNonNull(opts, "opts");
        ObjectNode body = mapper.createObjectNode();
        body.put("purpose", opts.purpose());
        putAliases(body, opts.expectedDevices());
        JsonNode data = post("api/v1/keys/challenge", body);
        JsonNode nonce = data.get("nonce");
        JsonNode keyChallenge = data.get("keyChallenge");
        JsonNode expiresAt = data.get("expiresAt");
        if (nonce == null || keyChallenge == null || expiresAt == null) {
            throw new RootHeraldApiException(200, "key challenge response missing nonce/keyChallenge/expiresAt");
        }
        return new KeyChallenge(nonce.asText(), keyChallenge.asText(), expiresAt.asText());
    }

    /**
     * POST {baseUrl}/api/v1/keys/certify — relay the client's {@code MintKey}
     * output under the key challenge's nonce and return the key RootHerald
     * registered: its {@code keyId}, public {@code jwk}, {@code alg}, and the
     * {@code deviceId} (alias) of the installation that certified it. Store
     * {@code keyId} and {@code jwk} against the alias; later signatures are
     * checked locally with {@link KeySignatures#verifyKeySignature(Jwk, byte[], byte[])}.
     * <p>
     * The certification is relayed verbatim, whichever platform shape it is:
     * {@code { publicArea, attest, signature }} from a TPM, or a
     * {@code platform}-tagged body from macOS or iOS. The key is the call's
     * only output, so a malformed one is refused with
     * {@link RootHeraldApiException} rather than returned half-parsed.
     *
     * @param nonce             {@link KeyChallenge#nonce()}
     * @param certificationJson the client's certification, a JSON object, passed through verbatim
     */
    public CertifiedKey certifyKey(String nonce, String certificationJson) {
        if (nonce == null || nonce.isEmpty()) {
            throw new IllegalArgumentException("nonce is required (from issueKeyChallenge)");
        }
        Objects.requireNonNull(certificationJson, "certificationJson");
        JsonNode certification = readObject(certificationJson, "certification");
        if (!isWellFormedCertification(certification)) {
            throw new IllegalArgumentException("certification must be { publicArea, attest, signature }"
                    + " from a TPM, or the platform form from macOS / iOS");
        }
        ObjectNode body = mapper.createObjectNode();
        body.put("nonce", nonce);
        body.set("certification", certification);
        return parseCertifiedKey(post("api/v1/keys/certify", body));
    }

    private static boolean isWellFormedCertification(JsonNode c) {
        if (c.path("platform").isTextual()) {
            return true;
        }
        return c.path("publicArea").isTextual() && c.path("attest").isTextual()
                && c.path("signature").isTextual();
    }

    /**
     * The JWK family must match {@code alg}: an EC key signs ES256 or agrees
     * ECDH-ES, an RSA key signs RS256 or wraps RSA-OAEP-256. Anything else is
     * refused rather than surfaced half-parsed: a caller that then verified a
     * signature with it would silently get {@code false}.
     */
    private CertifiedKey parseCertifiedKey(JsonNode node) {
        String deviceId = requireText(node, "deviceId");
        String keyId = requireText(node, "keyId");
        String purpose = requireText(node, "purpose");
        if (!KeyChallengeOptions.PURPOSE_SIGN.equals(purpose)
                && !KeyChallengeOptions.PURPOSE_DECRYPT.equals(purpose)) {
            throw new RootHeraldApiException(200, "certify response purpose is not sign/decrypt");
        }
        if (!node.path("hardwareBound").isBoolean()) {
            throw new RootHeraldApiException(200, "certify response missing hardwareBound");
        }
        Instant certifiedAt;
        try {
            certifiedAt = Instant.parse(requireText(node, "certifiedAt"));
        } catch (DateTimeParseException ex) {
            throw new RootHeraldApiException(200, "certify response certifiedAt is not an instant");
        }
        Jwk jwk = readJwk(node.get("jwk"));
        if (jwk == null) {
            throw new RootHeraldApiException(200, "certify response jwk is not an EC P-256 or RSA public key");
        }
        String alg = requireText(node, "alg");
        if (!(jwk.isEc() ? EC_ALGS : RSA_ALGS).contains(alg)) {
            throw new RootHeraldApiException(200,
                    "certify response alg " + alg + " does not fit a " + jwk.kty() + " key");
        }
        String format = textOrNull(node, "format");
        if (format != null && !KEY_FORMATS.contains(format)) {
            throw new RootHeraldApiException(200, "certify response format is not jwe/apple-ecies");
        }
        return new CertifiedKey(deviceId, keyId, purpose, alg, format, jwk,
                node.get("hardwareBound").asBoolean(), certifiedAt);
    }

    private static Jwk readJwk(JsonNode jwk) {
        if (jwk == null || !jwk.isObject()) {
            return null;
        }
        String kty = textOrNull(jwk, "kty");
        if (Jwk.KTY_EC.equals(kty) && Jwk.CRV_P256.equals(textOrNull(jwk, "crv"))
                && jwk.path("x").isTextual() && jwk.path("y").isTextual()) {
            return Jwk.ec(jwk.get("x").asText(), jwk.get("y").asText());
        }
        if (Jwk.KTY_RSA.equals(kty) && jwk.path("n").isTextual() && jwk.path("e").isTextual()) {
            return Jwk.rsa(jwk.get("n").asText(), jwk.get("e").asText());
        }
        return null;
    }

    private static String requireText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isEmpty()) {
            throw new RootHeraldApiException(200, "certify response missing " + field);
        }
        return value.asText();
    }

    // ── Ceremony 1: enroll ────────────────────────────────────────────────

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
     * <p>
     * Every enroll returns a challenge, including for a device already known:
     * each activation creates a new installation of the device with its own
     * AK blob, which the client keeps. The device's alias is returned by
     * {@link #relayActivate(EnrollActivationResponse)}, not here, and does not
     * change across installations.
     *
     * @param blob the client's enroll request blob
     */
    public RelayEnrollResult relayEnroll(EnrollRequestBlob blob) {
        Objects.requireNonNull(blob, "blob");

        ObjectNode body = mapper.createObjectNode();
        putIfSet(body, "ekPublicKey", blob.ekPublicKey());
        if (blob.attestationKey() != null) {
            ObjectNode ak = body.putObject("attestationKey");
            ak.put("publicArea", blob.attestationKey().publicArea());
            ak.put("parentPublicArea", blob.attestationKey().parentPublicArea());
            ak.put("qualifiedName", blob.attestationKey().qualifiedName());
        }
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

    private static void putAliases(ObjectNode node, List<String> aliases) {
        if (aliases != null) {
            ArrayNode out = node.putArray("expectedDevices");
            aliases.forEach(out::add);
        }
    }

    /**
     * As {@link #relayEnroll(EnrollRequestBlob)}, relaying the client's blob
     * verbatim as the JSON object it emitted: the bytes the client produced
     * are the bytes RootHerald receives, whatever fields they carry. This is
     * the path for a backend that holds the client's JSON and has no reason to
     * retype it.
     * <p>
     * Only the body's shape is checked, before any request: a TPM body carries
     * the nested {@code attestationKey}, a macOS body is flat, an iOS body has
     * its three fields. A flat TPM body is the 7.0 shape and is refused here
     * with {@link IllegalArgumentException}; the server would answer
     * {@code 400 wire_version_unsupported} anyway, and refusing locally keeps
     * the message specific.
     *
     * @param blobJson the client's enroll request blob, a JSON object
     */
    public RelayEnrollResult relayEnroll(String blobJson) {
        Objects.requireNonNull(blobJson, "blobJson");
        return relayEnroll(readObject(blobJson, "enroll blob"));
    }

    /**
     * As {@link #relayEnroll(String)}, for a backend that already parsed the
     * client's blob with Jackson. The node is sent as it is.
     *
     * @param blob the client's enroll request blob, a JSON object
     */
    public RelayEnrollResult relayEnroll(JsonNode blob) {
        Objects.requireNonNull(blob, "blob");
        if (!blob.isObject()) {
            throw new IllegalArgumentException("enroll blob must be a JSON object");
        }
        requireWellFormedEnrollBlob(blob);
        JsonNode data = post("api/v1/attest/enroll", blob);
        if (EnrollRequestBlob.PLATFORM_IOS.equals(blob.path("platform").asText(null)) && data.isEmpty()) {
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
     * The 8.0 TPM body nests the AK; macOS stays flat; iOS is its own shape.
     * Nothing inside the fields is read.
     */
    private static void requireWellFormedEnrollBlob(JsonNode blob) {
        String platform = blob.path("platform").asText(null);
        if (platform == null) {
            throw new IllegalArgumentException("enroll blob must carry platform");
        }
        switch (platform) {
            case EnrollRequestBlob.PLATFORM_WINDOWS, EnrollRequestBlob.PLATFORM_LINUX -> {
                JsonNode ak = blob.path("attestationKey");
                if (blob.has("akPublicArea") || !ak.isObject()
                        || !ak.path("publicArea").isTextual()
                        || !ak.path("parentPublicArea").isTextual()
                        || !ak.path("qualifiedName").isTextual()) {
                    throw new IllegalArgumentException("a " + platform + " enroll blob carries ekPublicKey and"
                            + " attestationKey { publicArea, parentPublicArea, qualifiedName }; a flat"
                            + " akPublicArea is the 7.0 shape and is refused");
                }
                if (!blob.path("ekPublicKey").isTextual()) {
                    throw new IllegalArgumentException("a " + platform + " enroll blob carries ekPublicKey");
                }
            }
            case EnrollRequestBlob.PLATFORM_MACOS -> {
                if (blob.has("attestationKey") || !blob.path("ekPublicKey").isTextual()
                        || !blob.path("akPublicArea").isTextual()) {
                    throw new IllegalArgumentException(
                            "a macos enroll blob carries ekPublicKey and akPublicArea and no attestationKey");
                }
            }
            case EnrollRequestBlob.PLATFORM_IOS -> {
                if (!blob.path("iosKeyId").isTextual() || !blob.path("iosAttestationObject").isTextual()
                        || !blob.path("nonce").isTextual()) {
                    throw new IllegalArgumentException(
                            "an ios enroll blob carries iosKeyId, iosAttestationObject and nonce");
                }
            }
            default -> throw new IllegalArgumentException(
                    "enroll blob platform must be windows, linux, macos or ios (got " + platform + ")");
        }
    }

    /**
     * Enroll relay — leg 2. POST {baseUrl}/api/v1/attest/activate.
     * <p>
     * Relays the client's {@code EnrollComplete()} blob to RootHerald, closing
     * the enrollment that {@link #relayEnroll(EnrollRequestBlob)} opened. The
     * server finds it by {@code enrollmentId} and checks the proof against the
     * platform it recorded; an unknown, spent or foreign id, a wrong proof and
     * a cross-tenant AK collision are refused alike, with 401.
     *
     * @param activation the client's activation response
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
        return node.hasNonNull(field) && node.get(field).isTextual() ? node.get(field).asText() : null;
    }

    /** Parse a caller-supplied JSON object, refusing anything else before a request is made. */
    private JsonNode readObject(String json, String what) {
        JsonNode node;
        try {
            node = mapper.readTree(json);
        } catch (IOException ex) {
            throw new RootHeraldException(what + " must be valid JSON: " + ex.getMessage(), ex);
        }
        if (node == null || !node.isObject()) {
            throw new RootHeraldException(what + " must be a JSON object");
        }
        return node;
    }

    // ── transport ─────────────────────────────────────────────────────────

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
            case 409 -> CODE_KEY_ROTATION_CONFLICT.equals(code) ? null : new ChallengeException(code, message);
            case 400 -> InvalidAskException.ERROR_CODE.equals(code)
                    || InvalidAskException.PURPOSE_ERROR_CODE.equals(code)
                    ? new InvalidAskException(code, message)
                    : new InvalidEvidenceException(code, message);
            case 429 -> QuotaExceededException.ERROR_CODE.equals(code)
                    || resp.headers().firstValue(QUOTA_HEADER).isPresent()
                    ? new QuotaExceededException(code, message, extractBudget(tree))
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

    /** The body's {@code budget { id, name }}, or {@code null}. */
    private static RefusingBudget extractBudget(JsonNode tree) {
        JsonNode budget = tree == null ? null : tree.get("budget");
        if (budget == null || !budget.isObject()
                || !budget.path("id").isTextual() || !budget.path("name").isTextual()) {
            return null;
        }
        return new RefusingBudget(budget.get("id").asText(), budget.get("name").asText());
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
