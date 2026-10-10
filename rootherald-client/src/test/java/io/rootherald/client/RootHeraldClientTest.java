package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.rootherald.ActivationRefusedException;
import io.rootherald.AdmissionRefusedException;
import io.rootherald.ChallengeException;
import io.rootherald.ExpectedNotEnforcedException;
import io.rootherald.InvalidAskException;
import io.rootherald.InvalidEvidenceException;
import io.rootherald.InvalidSecretKeyException;
import io.rootherald.QuotaExceededException;
import io.rootherald.RateLimitedException;
import io.rootherald.RootHeraldApiException;
import io.rootherald.RootHeraldException;
import io.rootherald.UnknownPolicyException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class RootHeraldClientTest {

    private HttpServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();
    private final AtomicReference<String> lastQuery = new AtomicReference<>();
    private final AtomicReference<String> lastPath = new AtomicReference<>();
    private final ObjectMapper mapper = new ObjectMapper();

    @AfterEach
    void teardown() {
        if (server != null) server.stop(0);
    }

    private RootHeraldClient start(String path, int status, String responseJson, String... headers)
            throws IOException {
        return startWith(path, exchange -> {
            try {
                lastAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
                lastQuery.set(exchange.getRequestURI().getRawQuery());
                lastPath.set(exchange.getRequestURI().getRawPath());
                lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                byte[] body = responseJson.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                for (int i = 0; i + 1 < headers.length; i += 2) {
                    exchange.getResponseHeaders().add(headers[i], headers[i + 1]);
                }
                exchange.sendResponseHeaders(status, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }, path);
    }

    private RootHeraldClient startWith(String path, Consumer<HttpExchange> handler, String contextPath)
            throws IOException {
        if (server != null) {
            server.stop(0);
        }
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(contextPath, handler::accept);
        server.start();
        return RootHeraldClient.builder()
                .secretKey("rh_sk_test_xxx")
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .build();
    }

    /** A client whose server answers nothing: for input the SDK must refuse before any request. */
    private static RootHeraldClient offline() {
        return RootHeraldClient.builder().secretKey("rh_sk_test_xxx").build();
    }

    private static EnrollRequestBlob.Builder tpmBlob(String platform) {
        return EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .attestationKey("akpub==", "parent==", "qn==")
                .platform(platform);
    }

    @Test
    void rejectsInvalidPrefixKey() {
        assertThrows(IllegalArgumentException.class,
                () -> RootHeraldClient.builder().secretKey("rh_bogus_abc"));
    }

    @Test
    void rejectsEmptyKey() {
        assertThrows(IllegalArgumentException.class,
                () -> RootHeraldClient.builder().secretKey(""));
    }

    // ── the challenge carries the ask ────────────────────────────────────

    private static final String CHALLENGE_WITH_ASK =
            "{\"nonce\":\"n_1\",\"challenge\":\"rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0\","
                    + "\"expiresAt\":\"2030-01-01T00:00:00Z\"}";

    @Test
    void issueChallengeSendsBearerSecret() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200, CHALLENGE_WITH_ASK);
        Challenge challenge = client.issueChallenge();
        assertEquals("n_1", challenge.nonce());
        assertEquals("rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0", challenge.challenge());
        assertEquals("2030-01-01T00:00:00Z", challenge.expiresAt());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
        assertEquals(0, mapper.readTree(lastBody.get()).size());
    }

    @Test
    void issueChallengeRequiresNonceChallengeAndExpiry() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200,
                "{\"nonce\":\"n_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class, client::issueChallenge);
        assertTrue(ex.getMessage().contains("nonce/challenge/expiresAt"));
        RootHeraldClient noId = start("/api/v1/attest/challenge", 200,
                "{\"challengeId\":\"ch_1\",\"nonce\":\"n_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        assertThrows(RootHeraldApiException.class, noId::issueChallenge);
    }

    @Test
    void issueChallengeSendsTheAskAndTheBindingAndNeverAPolicy() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200, CHALLENGE_WITH_ASK);
        Challenge challenge = client.issueChallenge(ChallengeOptions.defaults()
                .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_POSTURE)
                .expectedKey("key_1")
                .expectedDevices("dev-9", "dev-10"));
        assertEquals("n_1", challenge.nonce());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals(List.of("identity", "posture"), List.of(
                sent.get("ask").get(0).asText(), sent.get("ask").get(1).asText()));
        assertEquals("key_1", sent.get("expectedKey").asText());
        assertEquals(2, sent.get("expectedDevices").size());
        assertEquals("dev-10", sent.get("expectedDevices").get(1).asText());
        assertEquals(3, sent.size());
        assertFalse(sent.has("policy"));
        assertFalse(sent.has("keyPurpose"));
        assertFalse(sent.has("deviceHint"));
    }

    @Test
    void issueChallengeDefaultsOmitEveryOptionalField() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200, CHALLENGE_WITH_ASK);
        client.issueChallenge(ChallengeOptions.defaults());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals(0, sent.size());
        // An empty ask means the server default, so it is not sent either.
        client.issueChallenge(ChallengeOptions.defaults().ask(List.of()));
        assertEquals(0, mapper.readTree(lastBody.get()).size());
    }

    @Test
    void anEmptyBindingIsRefusedBeforeAnyRequest() {
        assertThrows(IllegalArgumentException.class, () -> ChallengeOptions.defaults().expectedKey(""));
        assertThrows(IllegalArgumentException.class, () -> ChallengeOptions.defaults().expectedDevices(List.of()));
        assertThrows(IllegalArgumentException.class, () -> ChallengeOptions.defaults().expectedDevices("a", ""));
        assertThrows(IllegalArgumentException.class, () -> AttestOptions.of("n_1").expectedKey(""));
        assertThrows(IllegalArgumentException.class, () -> AttestOptions.of("n_1").expectedDevices(List.of()));
        assertThrows(IllegalArgumentException.class, () -> KeyChallengeOptions.of("sign").expectedDevices(""));
    }

    @Test
    void aKeyAskIsAProgrammingErrorNotADeviceFailure() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 400,
                "{\"error\":\"invalid_ask\",\"message\":\"key is not an ask\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.issueChallenge(ChallengeOptions.defaults().ask("identity", "key")));
        assertTrue(ex instanceof InvalidAskException);
        assertFalse(ex instanceof InvalidEvidenceException);
        assertEquals("invalid_ask", ex.errorCode());
        assertEquals("key is not an ask", ex.getMessage());
    }

    @Test
    void anUnknownExpectedValueStaysGenericWithTheCode() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 422,
                "{\"error\":\"expected_unknown\",\"message\":\"no such device\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.issueChallenge(ChallengeOptions.defaults().expectedDevices("dev-x")));
        assertFalse(ex instanceof UnknownPolicyException);
        assertEquals("expected_unknown", ex.errorCode());
    }

    // ── verify: the verdict echoes the binding ───────────────────────────

    private static final String BOUND_VERDICT =
            "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"},"
                    + "\"expected\":{\"key\":\"key_1\",\"devices\":[\"dev-9\",\"dev-10\"]}}}";

    @Test
    void verifyAcceptsAVerdictThatEchoesTheBinding() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, BOUND_VERDICT);
        AttestResult result = client.verify("{}", AttestOptions.of("n_1")
                .expectedKey("key_1").expectedDevices("dev-10", "dev-9"));
        assertTrue(result.isPass());
        ExpectedBinding expected = result.expected().orElseThrow();
        assertEquals("key_1", expected.key());
        assertEquals(List.of("dev-9", "dev-10"), expected.devices());
        // The binding is enforced server-side; the request body does not repeat it.
        JsonNode sent = mapper.readTree(lastBody.get());
        assertFalse(sent.has("expectedKey"));
        assertFalse(sent.has("expectedDevices"));
    }

    @Test
    void verifyRefusesAVerdictThatDoesNotEchoTheBinding() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}}");
        assertThrows(ExpectedNotEnforcedException.class,
                () -> client.verify("{}", AttestOptions.of("n_1").expectedKey("key_1")));
        assertThrows(ExpectedNotEnforcedException.class,
                () -> client.verify("{}", AttestOptions.of("n_1").expectedDevices("dev-9")));
        // Echoed, but not what was asked.
        RootHeraldClient other = start("/api/v1/attest/verify", 200, BOUND_VERDICT);
        assertThrows(ExpectedNotEnforcedException.class,
                () -> other.verify("{}", AttestOptions.of("n_1").expectedKey("key_2")));
        assertThrows(ExpectedNotEnforcedException.class,
                () -> other.verify("{}", AttestOptions.of("n_1").expectedDevices("dev-9")));
        // A passing verdict naming a device outside the set.
        RootHeraldClient outside = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-11\"},"
                        + "\"expected\":{\"devices\":[\"dev-9\"]}}}");
        assertThrows(ExpectedNotEnforcedException.class,
                () -> outside.verify("{}", AttestOptions.of("n_1").expectedDevices("dev-9")));
    }

    @Test
    void verifyWithoutABindingIgnoresTheEcho() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, BOUND_VERDICT);
        assertTrue(client.verify("{}", AttestOptions.of("n_1")).isPass());
        RootHeraldClient plain = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        assertTrue(plain.verify("{}", AttestOptions.of("n_1")).expected().isEmpty());
    }

    @Test
    void aFailingVerdictAgainstAnotherDeviceIsAVerdictNotAnError() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"fail\",\"ueid\":\"dev-11\"},"
                        + "\"expected\":{\"devices\":[\"dev-9\"]}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1").expectedDevices("dev-9"));
        assertEquals(Verdict.FAIL, result.verdict());
        assertEquals("dev-11", result.deviceId().orElseThrow());
    }

    @Test
    void verifyReleasesNoKey() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}},"
                        + "\"key\":{\"keyId\":\"key_1\",\"jwk\":{\"kty\":\"EC\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertTrue(result.isPass());
        assertFalse(result.verdictNode().has("key"));
    }

    @Test
    void deviceIdReadsTheAlias() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        assertEquals("dev-9", client.verify("{}", AttestOptions.of("n_1")).deviceId().orElseThrow());
        RootHeraldClient withheld = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"disclosureClass\":\"verdict\"}}}");
        assertTrue(withheld.verify("{}", AttestOptions.of("n_1")).deviceId().isEmpty());
        RootHeraldClient blank = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\" \"}}}");
        assertTrue(blank.verify("{}", AttestOptions.of("n_1")).deviceId().isEmpty());
    }

    @Test
    void errorCodeRidesOnEveryTypedException() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 422,
                "{\"error\":\"unknown_policy\"}");
        UnknownPolicyException ex = assertThrows(UnknownPolicyException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
        assertEquals("unknown_policy", ex.errorCode());
        RootHeraldClient conflicting = start("/api/v1/attest/verify", 409,
                "{\"error\":\"challenge_expired_or_used\",\"detail\":\"used\"}");
        ChallengeException ch = assertThrows(ChallengeException.class,
                () -> conflicting.verify("{}", AttestOptions.of("n_1")));
        assertEquals("challenge_expired_or_used", ch.errorCode());
        assertEquals("used", ch.getMessage());
    }

    // ── mint a key ───────────────────────────────────────────────────────

    private static final String KEY_CHALLENGE =
            "{\"nonce\":\"k_1\",\"keyChallenge\":\"rhk1c.bm9uY2U.eyJwdXJwb3NlIjoic2lnbiJ9\","
                    + "\"expiresAt\":\"2030-01-01T00:00:00Z\"}";

    private static final String TPM_CERTIFICATION =
            "{\"publicArea\":\"pub==\",\"attest\":\"att==\",\"signature\":\"sig==\",\"futureField\":1}";

    private static final String CERTIFIED_EC =
            "{\"deviceId\":\"dev-9\",\"keyId\":\"key_1\",\"purpose\":\"sign\",\"alg\":\"ES256\","
                    + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"eHg\",\"y\":\"eXk\"},"
                    + "\"hardwareBound\":true,\"certifiedAt\":\"2030-01-01T00:01:00Z\"}";

    @Test
    void issueKeyChallengeSendsThePurposeAndTheBinding() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/challenge", 200, KEY_CHALLENGE);
        KeyChallenge challenge = client.issueKeyChallenge(
                KeyChallengeOptions.of(KeyChallengeOptions.PURPOSE_SIGN).expectedDevices("dev-9"));
        assertEquals("k_1", challenge.nonce());
        assertEquals("rhk1c.bm9uY2U.eyJwdXJwb3NlIjoic2lnbiJ9", challenge.keyChallenge());
        assertEquals("2030-01-01T00:00:00Z", challenge.expiresAt());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("sign", sent.get("purpose").asText());
        assertEquals("dev-9", sent.get("expectedDevices").get(0).asText());
        assertEquals(2, sent.size());

        client.issueKeyChallenge("decrypt");
        sent = mapper.readTree(lastBody.get());
        assertEquals("decrypt", sent.get("purpose").asText());
        assertEquals(1, sent.size());
    }

    @Test
    void issueKeyChallengeRefusesAnUnknownPurposeAndAShortResponse() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> offline().issueKeyChallenge("wrap"));
        RootHeraldClient client = start("/api/v1/keys/challenge", 200,
                "{\"nonce\":\"k_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.issueKeyChallenge("sign"));
        assertTrue(ex.getMessage().contains("nonce/keyChallenge/expiresAt"));
    }

    @Test
    void certifyKeyRelaysTheCertificationVerbatimAndReturnsTheKey() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/certify", 200, CERTIFIED_EC);
        CertifiedKey key = client.certifyKey("k_1", TPM_CERTIFICATION);
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("k_1", sent.get("nonce").asText());
        assertEquals(mapper.readTree(TPM_CERTIFICATION), sent.get("certification"));
        assertEquals("dev-9", key.deviceId());
        assertEquals("key_1", key.keyId());
        assertEquals("sign", key.purpose());
        assertEquals("ES256", key.alg());
        assertNull(key.format());
        assertEquals(Jwk.ec("eHg", "eXk"), key.jwk());
        assertTrue(key.hardwareBound());
        assertEquals(Instant.parse("2030-01-01T00:01:00Z"), key.certifiedAt());
    }

    @Test
    void certifyKeyAcceptsThePlatformCertifications() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/certify", 200,
                "{\"deviceId\":\"dev-m\",\"keyId\":\"key_m\",\"purpose\":\"sign\",\"alg\":\"ES256\","
                        + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"eHg\",\"y\":\"eXk\"},"
                        + "\"hardwareBound\":false,\"certifiedAt\":\"2030-01-01T00:01:00Z\"}");
        CertifiedKey mac = client.certifyKey("k_1",
                "{\"platform\":\"macos\",\"publicKey\":\"pk==\",\"signature\":\"sig==\"}");
        assertFalse(mac.hardwareBound());
        assertEquals("macos", mapper.readTree(lastBody.get()).get("certification").get("platform").asText());
        client.certifyKey("k_1", "{\"platform\":\"ios\",\"keyId\":\"kid==\",\"assertion\":\"as==\"}");
        assertEquals("as==", mapper.readTree(lastBody.get()).get("certification").get("assertion").asText());
    }

    @Test
    void certifyKeyReturnsAnRsaKey() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/certify", 200,
                "{\"deviceId\":\"dev-9\",\"keyId\":\"key_2\",\"purpose\":\"sign\",\"alg\":\"RS256\","
                        + "\"jwk\":{\"kty\":\"RSA\",\"n\":\"bW9k\",\"e\":\"AQAB\"},"
                        + "\"hardwareBound\":true,\"certifiedAt\":\"2030-01-01T00:01:00Z\"}");
        CertifiedKey key = client.certifyKey("k_1", TPM_CERTIFICATION);
        assertEquals(Jwk.rsa("bW9k", "AQAB"), key.jwk());
        assertTrue(key.jwk().isRsa());
        assertEquals("RS256", key.alg());
    }

    @Test
    void certifyKeyReturnsADecryptKeyWithItsFormat() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/certify", 200,
                "{\"deviceId\":\"dev-9\",\"keyId\":\"key_3\",\"purpose\":\"decrypt\",\"alg\":\"ECDH-ES\","
                        + "\"format\":\"jwe\","
                        + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"eHg\",\"y\":\"eXk\"},"
                        + "\"hardwareBound\":true,\"certifiedAt\":\"2030-01-01T00:01:00Z\"}");
        CertifiedKey key = client.certifyKey("k_1", TPM_CERTIFICATION);
        assertEquals("decrypt", key.purpose());
        assertEquals("jwe", key.format());
    }

    @Test
    void certifyKeyRefusesAMalformedKey() throws Exception {
        String[] bad = {
            "{\"keyId\":\"key_1\"}",
            CERTIFIED_EC.replace("\"deviceId\":\"dev-9\",", ""),
            CERTIFIED_EC.replace("\"hardwareBound\":true,", ""),
            CERTIFIED_EC.replace("ES256", "RS256"),
            CERTIFIED_EC.replace("ES256", "HS256"),
            CERTIFIED_EC.replace("\"crv\":\"P-256\"", "\"crv\":\"P-384\""),
            CERTIFIED_EC.replace("\"purpose\":\"sign\"", "\"purpose\":\"wrap\""),
            CERTIFIED_EC.replace("2030-01-01T00:01:00Z", "tomorrow"),
            CERTIFIED_EC.replace("\"alg\"", "\"format\":\"pem\",\"alg\""),
        };
        for (String response : bad) {
            RootHeraldClient client = start("/api/v1/keys/certify", 200, response);
            assertThrows(RootHeraldApiException.class,
                    () -> client.certifyKey("k_1", TPM_CERTIFICATION), response);
        }
    }

    @Test
    void certifyKeyRefusesBadInputBeforeAnyRequest() {
        RootHeraldClient client = offline();
        assertThrows(IllegalArgumentException.class, () -> client.certifyKey("", TPM_CERTIFICATION));
        assertThrows(IllegalArgumentException.class, () -> client.certifyKey("k_1", "{\"publicArea\":\"pub==\"}"));
        assertThrows(IllegalArgumentException.class, () -> client.certifyKey("k_1", "{}"));
        assertThrows(RootHeraldException.class, () -> client.certifyKey("k_1", "not json"));
        assertThrows(RootHeraldException.class, () -> client.certifyKey("k_1", "[]"));
    }

    @Test
    void aKeyRotationConflictStaysGenericWithTheCode() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/certify", 409,
                "{\"error\":\"key_rotation_conflict\",\"message\":\"rotating\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.certifyKey("k_1", TPM_CERTIFICATION));
        assertFalse(ex instanceof ChallengeException);
        assertEquals(409, ex.statusCode());
        assertEquals("key_rotation_conflict", ex.errorCode());
        RootHeraldClient spent = start("/api/v1/keys/certify", 409,
                "{\"error\":\"challenge_expired_or_used\"}");
        assertThrows(ChallengeException.class, () -> spent.certifyKey("k_1", TPM_CERTIFICATION));
    }

    @Test
    void aDisclosureCeilingTooLowForAKeyStaysGenericWithTheCode() throws Exception {
        RootHeraldClient client = start("/api/v1/keys/challenge", 422,
                "{\"error\":\"key_disclosure_too_low\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.issueKeyChallenge("sign"));
        assertFalse(ex instanceof UnknownPolicyException);
        assertEquals("key_disclosure_too_low", ex.errorCode());
    }

    // ── enroll ───────────────────────────────────────────────────────────

    private static final String TPM_ENROLL_201 =
            "{\"enrollmentId\":\"enr-1\",\"credentialBlob\":\"cb==\",\"encryptedSecret\":\"es==\"}";

    @Test
    void relayEnrollSendsNoQueryString() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll(tpmBlob("windows").build());
        assertNull(lastQuery.get());
    }

    @Test
    void typedEnrollBlobCarriesEverythingSetAndNothingElse() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll(tpmBlob("linux")
                .tpmSelfReport("IFX", "SLB9670")
                .build());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("ekpub==", sent.get("ekPublicKey").asText());
        assertEquals("akpub==", sent.get("attestationKey").get("publicArea").asText());
        assertEquals("parent==", sent.get("attestationKey").get("parentPublicArea").asText());
        assertEquals("qn==", sent.get("attestationKey").get("qualifiedName").asText());
        assertEquals(3, sent.get("attestationKey").size());
        assertEquals("IFX", sent.get("tpmSelfReport").get("manufacturer").asText());
        assertEquals("SLB9670", sent.get("tpmSelfReport").get("vendorString").asText());
        assertEquals(4, sent.size());
        assertFalse(sent.has("akPublicArea"));
        assertFalse(sent.has("ekCertPem"));
        assertFalse(sent.has("iosKeyId"));
    }

    @Test
    void typedEnrollBlobBuildsAnAppAttestBody() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, "{}");
        RelayEnrollResult result = client.relayEnroll(EnrollRequestBlob.builder()
                .platform("ios")
                .iosKeyId("k==")
                .iosAttestationObject("att==")
                .nonce("bm9uY2U")
                .build());
        assertTrue(result.challenge().isEmpty());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals(4, sent.size());
        assertEquals("ios", sent.get("platform").asText());
        assertEquals("k==", sent.get("iosKeyId").asText());
        assertEquals("att==", sent.get("iosAttestationObject").asText());
        assertEquals("bm9uY2U", sent.get("nonce").asText());
    }

    @Test
    void typedEnrollBlobRequiresThePlatformAndItsShape() {
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==").attestationKey("a", "p", "q").build());
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("ios").iosKeyId("k==").iosAttestationObject("att==").build());
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("windows").ekPublicKey("ekpub==").build());
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("linux").attestationKey("a", "p", "q").build());
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("android").ekPublicKey("ekpub==").attestationKey("a", "p", "q").build());
        assertThrows(IllegalArgumentException.class, () -> new AttestationKey("a", "", "q"));
    }

    @Test
    void aFlatTpmBodyIsTheOldShapeAndIsRefusedBeforeAnyRequest() {
        RootHeraldClient client = offline();
        // The typed record: a TPM body with akPublicArea, or without attestationKey.
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("windows").ekPublicKey("ekpub==").akPublicArea("akpub==").build());
        assertThrows(IllegalArgumentException.class, () -> tpmBlob("windows").akPublicArea("akpub==").build());
        // A macOS body stays flat; nesting is not its shape.
        assertThrows(IllegalArgumentException.class, () -> tpmBlob("macos").build());
        // The verbatim paths check the same shapes and make no request.
        String flat = "{\"ekPublicKey\":\"ekpub==\",\"akPublicArea\":\"akpub==\",\"platform\":\"linux\"}";
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll(flat));
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll(mapper.readTree(flat)));
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll(
                "{\"ekPublicKey\":\"ekpub==\",\"attestationKey\":{\"publicArea\":\"a\"},\"platform\":\"linux\"}"));
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll(
                "{\"ekPublicKey\":\"ekpub==\",\"akPublicArea\":\"akpub==\",\"platform\":\"macos\","
                        + "\"attestationKey\":{\"publicArea\":\"a\",\"parentPublicArea\":\"p\",\"qualifiedName\":\"q\"}}"));
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll(
                "{\"platform\":\"ios\",\"iosKeyId\":\"k==\"}"));
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll("{\"ekPublicKey\":\"ekpub==\"}"));
    }

    @Test
    void relayEnrollSecureEnclaveReturnsTheChallengeNonce() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201,
                "{\"enrollmentId\":\"enr-2\",\"challengeNonce\":\"cn==\"}");
        RelayEnrollResult result = client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("sepub==")
                .akPublicArea("sepub==")
                .platform("macos")
                .build());
        EnrollActivationChallenge challenge = result.challenge().orElseThrow();
        assertEquals("enr-2", challenge.enrollmentId());
        assertEquals("cn==", challenge.challengeNonce());
        assertNull(challenge.credentialBlob());
        assertNull(challenge.encryptedSecret());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("sepub==", sent.get("akPublicArea").asText());
        assertFalse(sent.has("attestationKey"));
    }

    private static final String NESTED_ENROLL_JSON =
            "{\"ekPublicKey\":\"ekpub==\",\"attestationKey\":{\"publicArea\":\"akpub==\","
                    + "\"parentPublicArea\":\"parent==\",\"qualifiedName\":\"qn==\",\"futureField\":true},"
                    + "\"platform\":\"linux\",\"tpmSelfReport\":{\"manufacturer\":\"IFX\","
                    + "\"vendorString\":\"SLB9670\"},\"futureField\":[1,2]}";

    @Test
    void relayEnrollRelaysAJsonBlobVerbatim() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll(NESTED_ENROLL_JSON);
        assertEquals(mapper.readTree(NESTED_ENROLL_JSON), mapper.readTree(lastBody.get()));
        assertNull(lastQuery.get());
    }

    @Test
    void relayEnrollRelaysAJacksonNodeVerbatim() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        JsonNode blob = mapper.readTree(NESTED_ENROLL_JSON);
        RelayEnrollResult result = client.relayEnroll(blob);
        assertEquals("enr-1", result.challenge().orElseThrow().enrollmentId());
        assertEquals(blob, mapper.readTree(lastBody.get()));
    }

    @Test
    void relayEnrollAppAttestAcceptsAnEmpty201() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, "{}");
        RelayEnrollResult result = client.relayEnroll("{\"platform\":\"ios\",\"iosKeyId\":\"k==\","
                + "\"iosAttestationObject\":\"att==\",\"nonce\":\"bm9uY2U\"}");
        assertTrue(result.challenge().isEmpty());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("ios", sent.get("platform").asText());
        assertEquals("bm9uY2U", sent.get("nonce").asText());
    }

    @Test
    void relayEnrollRejectsAnEmpty201ForATpm() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, "{}");
        assertThrows(RootHeraldApiException.class, () -> client.relayEnroll(tpmBlob("windows").build()));
    }

    @Test
    void relayEnrollRejectsA201WithoutEnrollmentIdOrProofMaterial() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201,
                "{\"deviceId\":\"dev-1\",\"credentialBlob\":\"cb==\",\"encryptedSecret\":\"es==\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.relayEnroll(tpmBlob("windows").build()));
        assertTrue(ex.getMessage().contains("enrollmentId"));
        RootHeraldClient halfTpm = start("/api/v1/attest/enroll", 201,
                "{\"enrollmentId\":\"enr-1\",\"credentialBlob\":\"cb==\"}");
        assertThrows(RootHeraldApiException.class,
                () -> halfTpm.relayEnroll(tpmBlob("windows").build()));
    }

    @Test
    void relayEnrollRejectsABlobThatIsNotAJsonObject() {
        RootHeraldClient client = offline();
        assertThrows(RootHeraldException.class, () -> client.relayEnroll("not json"));
        assertThrows(RootHeraldException.class, () -> client.relayEnroll("[]"));
        assertThrows(IllegalArgumentException.class, () -> client.relayEnroll(mapper.createArrayNode()));
    }

    @Test
    void relayEnrollMaps422AdmissionRefused() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 422,
                "{\"error\":\"admission_refused\",\"detail\":\"firmware TPM under a discrete-only policy\"}");
        AdmissionRefusedException ex = assertThrows(AdmissionRefusedException.class,
                () -> client.relayEnroll(tpmBlob("windows").build()));
        assertEquals("admission_refused", ex.errorCode());
        assertEquals("firmware TPM under a discrete-only policy", ex.getMessage());
    }

    @Test
    void theServersShapeRefusalsAreInvalidEvidenceWithTheCode() throws Exception {
        for (String code : new String[] {"wire_version_unsupported", "invalid_enroll_shape"}) {
            RootHeraldClient client = start("/api/v1/attest/enroll", 400, "{\"error\":\"" + code + "\"}");
            InvalidEvidenceException ex = assertThrows(InvalidEvidenceException.class,
                    () -> client.relayEnroll(tpmBlob("windows").build()));
            assertEquals(code, ex.errorCode());
        }
    }

    // The REAL server wire shape (camelCase, from platform BackgroundCheckDtos):
    // the pass/fail token lives at verdict.device.verdict, and assuranceClaimsMet
    // + enrollmentRequired are top-level siblings of `verdict`.
    private static final String PASSING_VERDICT =
            "{\"verdict\":{\"acr\":\"urn:acr:hw\",\"amr\":[\"hwk\"],"
                    + "\"authTime\":\"2030-01-01T00:00:00Z\",\"expiresAt\":\"2030-01-01T00:05:00Z\","
                    + "\"device\":{\"ueid\":\"dev-9\",\"disclosureClass\":\"pseudonymous\","
                    + "\"earStatus\":\"affirming\",\"verdict\":\"pass\",\"attestationType\":\"tpm20\","
                    + "\"attestedAt\":\"2030-01-01T00:00:00Z\",\"quoteVerified\":true,"
                    + "\"secureBootVerified\":true,\"eventLogVerified\":true,\"platform\":\"windows\"}},"
                    + "\"assuranceClaimsMet\":[\"urn:rootherald:assurance:hardware-backed\"],"
                    + "\"enrollmentRequired\":false}";

    @Test
    void attestPassVerdict() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        AttestResult result = client.verify("{\"quote\":\"...\",\"logs\":{\"srtm\":\"bG9n\"}}",
                AttestOptions.of("n_1"));
        // A genuinely PASSING device (token at verdict.device.verdict) is a pass.
        assertEquals(Verdict.PASS, result.verdict());
        assertTrue(result.isPass());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("n_1", sent.get("nonce").asText());
        assertFalse(sent.has("challengeId"));
        assertEquals("...", sent.get("evidence").get("quote").asText());
        assertEquals("bG9n", sent.get("evidence").get("logs").get("srtm").asText());
        assertFalse(sent.has("policy"));
    }

    @Test
    void verifyRequiresANonce() {
        assertThrows(IllegalArgumentException.class, () -> AttestOptions.of(""));
        assertThrows(IllegalArgumentException.class, () -> AttestOptions.of(null));
    }

    @Test
    void exposesTopLevelParityFields() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertEquals(List.of("urn:rootherald:assurance:hardware-backed"),
                result.assuranceClaimsMet());
        assertFalse(result.enrollmentRequired());
    }

    @Test
    void surfacesEnrollmentRequiredSignal() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"fail\"}},"
                        + "\"assuranceClaimsMet\":[],\"enrollmentRequired\":true}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertTrue(result.enrollmentRequired());
        assertTrue(result.assuranceClaimsMet().isEmpty());
        assertEquals(Verdict.FAIL, result.verdict());
    }

    @Test
    void parityFieldsDefaultWhenAbsent() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertTrue(result.assuranceClaimsMet().isEmpty());
        assertFalse(result.enrollmentRequired());
    }

    @Test
    void sendsRequestedDisclosureClassWhenSet() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        client.verify("{}", AttestOptions.of("n_1").requestedDisclosureClass("pseudonymous"));
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("pseudonymous", sent.get("requestedDisclosureClass").asText());
    }

    @Test
    void omitsRequestedDisclosureClassWhenUnset() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        client.verify("{}", AttestOptions.of("n_1"));
        JsonNode sent = mapper.readTree(lastBody.get());
        assertFalse(sent.has("requestedDisclosureClass"));
    }

    @Test
    void exposesCohortFields() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{"
                        + "\"verdict\":\"pass\",\"ueid\":\"dev-9\","
                        + "\"cohortKey\":\"tpm20:win11:sb1:abc123\","
                        + "\"cohortScope\":\"tenant-fleet\","
                        + "\"cohortPrevalence\":0.042,"
                        + "\"cohortPrevalencePerPcr\":{\"0\":0.9,\"7\":0.5},"
                        + "\"cohortSampleSize\":1287,"
                        + "\"novelProfile\":false}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertEquals("tpm20:win11:sb1:abc123", result.cohortKey());
        assertEquals("tenant-fleet", result.cohortScope());
        assertEquals(0.042, result.cohortPrevalence());
        assertEquals(0.5, result.cohortPrevalencePerPcr().get("7"));
        assertEquals(1287L, result.cohortSampleSize());
        assertEquals(Boolean.FALSE, result.novelProfile());
    }

    @Test
    void cohortFieldsNullWhenAbsent() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertNull(result.cohortKey());
        assertNull(result.cohortPrevalence());
        assertNull(result.novelProfile());
        assertTrue(result.cohortPrevalencePerPcr().isEmpty());
    }

    @Test
    void failVerdictIsNotAnError() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"fail\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertEquals(Verdict.FAIL, result.verdict());
        assertFalse(result.isPass());
    }

    @Test
    void warnVerdictIsTheServersToken() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"warn\"}}}");
        assertEquals(Verdict.WARN, client.verify("{}", AttestOptions.of("n_1")).verdict());
    }

    @Test
    void aVerdictTokenOutsidePassWarnFailIsRefused() throws Exception {
        for (String token : new String[] {"\"allow\"", "\"review\"", "\"\"", "null", "7"}) {
            RootHeraldClient client = start("/api/v1/attest/verify", 200,
                    "{\"verdict\":{\"device\":{\"verdict\":" + token + "}}}");
            RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                    () -> client.verify("{}", AttestOptions.of("n_1")), token);
            assertTrue(ex.getMessage().contains("verdict.device.verdict"));
        }
    }

    @Test
    void aPathPrefixOnTheBaseUrlIsKept() throws Exception {
        RootHeraldClient client = startWith("/prefix/api/v1/attest/verify", exchange -> {
            try {
                lastPath.set(exchange.getRequestURI().getRawPath());
                byte[] body = "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}}}".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }, "/prefix/");
        RootHeraldClient prefixed = RootHeraldClient.builder()
                .secretKey("rh_sk_test_xxx")
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/prefix")
                .build();
        prefixed.verify("{}", AttestOptions.of("n_1"));
        assertEquals("/prefix/api/v1/attest/verify", lastPath.get());
        RootHeraldClient slashed = RootHeraldClient.builder()
                .secretKey("rh_sk_test_xxx")
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/prefix/")
                .build();
        slashed.verify("{}", AttestOptions.of("n_1"));
        assertEquals("/prefix/api/v1/attest/verify", lastPath.get());
        assertNotNull(client);
    }

    @Test
    void theRequestTimeoutIsThirtySeconds() {
        assertEquals(java.time.Duration.ofSeconds(30), RootHeraldClient.DEFAULT_TIMEOUT);
    }

    @Test
    void maps401ToInvalidSecretKey() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 401,
                "{\"error\":\"x\",\"message\":\"boom\"}");
        assertThrows(InvalidSecretKeyException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
        RootHeraldClient bare = start("/api/v1/attest/verify", 401, "");
        assertThrows(InvalidSecretKeyException.class,
                () -> bare.verify("{}", AttestOptions.of("n_1")));
    }

    @Test
    void maps401ActivationRefusedToItsOwnType() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 401,
                "{\"error\":\"activation_refused\",\"message\":\"Invalid credential activation response\"}");
        ActivationRefusedException ex = assertThrows(ActivationRefusedException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
        assertEquals("activation_refused", ex.errorCode());
        assertEquals("Invalid credential activation response", ex.getMessage());
        assertEquals(401, ex.statusCode());
    }

    @Test
    void maps422ToUnknownPolicy() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 422,
                "{\"message\":\"no such policy\"}");
        assertThrows(UnknownPolicyException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
    }

    @Test
    void a422WithACodeNoTypeCoversStaysGenericWithTheCode() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 422,
                "{\"error\":\"posture_not_bound\",\"message\":\"no posture policy\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.issueChallenge());
        assertFalse(ex instanceof UnknownPolicyException);
        assertEquals(422, ex.statusCode());
        assertEquals("posture_not_bound", ex.errorCode());
        assertEquals("no posture policy", ex.getMessage());
    }

    @Test
    void a402PlanLapsedStaysGenericWithTheCode() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 402,
                "{\"error\":\"plan_lapsed\",\"message\":\"plan lapsed\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.issueChallenge());
        assertEquals(402, ex.statusCode());
        assertEquals("plan_lapsed", ex.errorCode());
    }

    @Test
    void maps409ToChallenge() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 409, "{}");
        assertThrows(ChallengeException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
    }

    @Test
    void maps400ToInvalidEvidence() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 400, "{}");
        assertThrows(InvalidEvidenceException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
    }

    @Test
    void maps429BudgetExhaustedByCodeOrHeaderAndNamesTheBudget() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 429,
                "{\"error\":\"budget_exhausted\",\"message\":\"ceiling\","
                        + "\"budget\":{\"id\":\"bud_1\",\"name\":\"Production\"}}");
        QuotaExceededException ex = assertThrows(QuotaExceededException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
        assertEquals("budget_exhausted", ex.errorCode());
        assertEquals("bud_1", ex.budget().id());
        assertEquals("Production", ex.budget().name());
        RootHeraldClient byHeader = start("/api/v1/attest/verify", 429, "{}",
                "X-RootHerald-Quota", "budget-exhausted");
        assertNull(assertThrows(QuotaExceededException.class,
                () -> byHeader.verify("{}", AttestOptions.of("n_1"))).budget());
    }

    @Test
    void maps429WithoutAQuotaSignalToRateLimited() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 429,
                "{\"error\":\"rate_limited\",\"message\":\"Too many requests\",\"retryAfterSeconds\":60}",
                "Retry-After", "17");
        RateLimitedException ex = assertThrows(RateLimitedException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
        assertEquals(17, ex.retryAfterSeconds());
        assertEquals("rate_limited", ex.errorCode());

        RootHeraldClient fromBody = start("/api/v1/attest/verify", 429,
                "{\"error\":\"rate_limited\",\"retryAfterSeconds\":60}");
        assertEquals(60, assertThrows(RateLimitedException.class,
                () -> fromBody.verify("{}", AttestOptions.of("n_1"))).retryAfterSeconds());

        RootHeraldClient bare = start("/api/v1/attest/verify", 429, "");
        assertNull(assertThrows(RateLimitedException.class,
                () -> bare.verify("{}", AttestOptions.of("n_1"))).retryAfterSeconds());
    }

    // ── ABI backend-relay contract ────────────────────────────────────────

    @Test
    void issueChallengeIsTheCanonicalName() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200, CHALLENGE_WITH_ASK);
        Challenge challenge = client.issueChallenge();
        assertEquals("n_1", challenge.nonce());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void verifyIsTheCanonicalName() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertTrue(result.isPass());
    }

    @Test
    void relayEnrollFreshReturnsChallenge() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        RelayEnrollResult result = client.relayEnroll(tpmBlob("windows").build());
        EnrollActivationChallenge challenge = result.challenge().orElseThrow();
        assertEquals("enr-1", challenge.enrollmentId());
        assertEquals("cb==", challenge.credentialBlob());
        assertEquals("es==", challenge.encryptedSecret());
        assertNull(challenge.challengeNonce());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void relayEnrollSendsCanonicalWireShape() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll(tpmBlob("linux")
                .ekCertPem("-----BEGIN CERT-----")
                .ekCertificateChain(List.of("int-a", "int-b"))
                .build());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("ekpub==", sent.get("ekPublicKey").asText());
        assertEquals("akpub==", sent.get("attestationKey").get("publicArea").asText());
        assertEquals("linux", sent.get("platform").asText());
        assertEquals("-----BEGIN CERT-----", sent.get("ekCertPem").asText());
        assertEquals(2, sent.get("ekCertificateChain").size());
        assertEquals("int-b", sent.get("ekCertificateChain").get(1).asText());
    }

    @Test
    void relayEnrollMapsAuthError() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 401,
                "{\"message\":\"bad key\"}");
        assertThrows(InvalidSecretKeyException.class,
                () -> client.relayEnroll(tpmBlob("windows").build()));
    }

    @Test
    void relayActivateReturnsTerminalBody() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/activate", 200,
                "{\"deviceId\":\"dev-1\",\"status\":\"enrolled\",\"enrolledAt\":\"2030-01-01T00:00:00Z\"}");
        RelayActivateResponse result = client.relayActivate(
                EnrollActivationResponse.ofDecryptedSecret("enr-1", "secret=="));
        assertEquals("dev-1", result.deviceId());
        assertEquals("enrolled", result.status());
        assertEquals("2030-01-01T00:00:00Z", result.enrolledAt());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("enr-1", sent.get("enrollmentId").asText());
        assertEquals("secret==", sent.get("decryptedSecret").asText());
        assertEquals(2, sent.size());
        assertFalse(sent.has("signature"));
        assertFalse(sent.has("deviceId"));
        assertFalse(sent.has("akPublicKey"));
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void relayActivateSendsASecureEnclaveSignature() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/activate", 200,
                "{\"deviceId\":\"dev-2\",\"status\":\"enrolled\"}");
        RelayActivateResponse result = client.relayActivate(
                EnrollActivationResponse.ofSignature("enr-2", "sig=="));
        assertEquals("dev-2", result.deviceId());
        assertNull(result.enrolledAt());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("enr-2", sent.get("enrollmentId").asText());
        assertEquals("sig==", sent.get("signature").asText());
        assertFalse(sent.has("decryptedSecret"));
    }

    @Test
    void relayActivateMapsARefusalToActivationRefusedNotInvalidKey() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/activate", 401,
                "{\"error\":\"activation_refused\",\"message\":\"Invalid credential activation response\"}");
        assertThrows(ActivationRefusedException.class, () -> client.relayActivate(
                EnrollActivationResponse.ofDecryptedSecret("enr-9", "secret==")));
        RootHeraldClient badKey = start("/api/v1/attest/activate", 401,
                "{\"error\":\"invalid_secret_key\"}");
        assertThrows(InvalidSecretKeyException.class, () -> badKey.relayActivate(
                EnrollActivationResponse.ofDecryptedSecret("enr-9", "secret==")));
    }

    @Test
    void activationResponseRequiresEnrollmentIdAndExactlyOneProof() {
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationResponse("", "secret==", null));
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationResponse("enr-1", "", null));
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationResponse("enr-1", null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationResponse("enr-1", "secret==", "sig=="));
    }

    @Test
    void activationChallengeRequiresEnrollmentIdAndProofMaterial() {
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationChallenge("", "cb==", "es==", null));
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationChallenge("enr-1", "cb==", null, null));
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationChallenge("enr-1", null, null, null));
        assertEquals("cn==", new EnrollActivationChallenge("enr-1", null, null, "cn==").challengeNonce());
    }
}
