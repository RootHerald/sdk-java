package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
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

    @Test
    void issueChallengeSendsBearerSecret() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200, CHALLENGE_WITH_ASK);
        Challenge challenge = client.issueChallenge("device-hint");
        assertEquals("n_1", challenge.nonce());
        assertEquals("rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19", challenge.challenge());
        assertEquals("2030-01-01T00:00:00Z", challenge.expiresAt());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("device-hint", sent.get("deviceHint").asText());
        assertFalse(sent.has("ask"));
    }

    // ── the challenge carries the ask ────────────────────────────────────

    private static final String CHALLENGE_WITH_ASK =
            "{\"nonce\":\"n_1\",\"challenge\":\"rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19\","
                    + "\"expiresAt\":\"2030-01-01T00:00:00Z\"}";

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
    void issueChallengeWithOptionsSendsTheAskAndNeverAPolicy() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/challenge", 200, CHALLENGE_WITH_ASK);
        Challenge challenge = client.issueChallenge(ChallengeOptions.defaults()
                .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_KEY)
                .keyPurpose(ChallengeOptions.KEY_PURPOSE_SIGN)
                .deviceHint("hint"));
        assertEquals("rhc1.bm9uY2U.eyJhc2siOlsia2V5Il19", challenge.challenge());
        assertEquals("n_1", challenge.nonce());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals(2, sent.get("ask").size());
        assertEquals("identity", sent.get("ask").get(0).asText());
        assertEquals("key", sent.get("ask").get(1).asText());
        assertFalse(sent.has("policy"));
        assertEquals("sign", sent.get("keyPurpose").asText());
        assertEquals("hint", sent.get("deviceHint").asText());
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

    private static final String PASSING_VERDICT_WITH_KEY =
            "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}},"
                    + "\"assuranceClaimsMet\":[],\"enrollmentRequired\":false,"
                    + "\"key\":{\"keyId\":\"key_1\","
                    + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"eHg\",\"y\":\"eXk\"},"
                    + "\"purpose\":\"sign\",\"authPolicy\":\"cG9saWN5\","
                    + "\"certifiedAt\":\"2030-01-01T00:01:00Z\"}}";

    @Test
    void verifyExposesTheCertifiedKeyFromTheResponseRoot() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT_WITH_KEY);
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertTrue(result.isPass());
        assertTrue(result.key().isPresent());
        CertifiedKey key = result.key().get();
        assertEquals("key_1", key.keyId());
        assertEquals(new Jwk("EC", "P-256", "eHg", "eXk"), key.jwk());
        assertEquals("sign", key.purpose());
        assertEquals("cG9saWN5", key.authPolicy());
        assertEquals(Instant.parse("2030-01-01T00:01:00Z"), key.certifiedAt());
    }

    @Test
    void verifyKeyIsEmptyWhenAbsent() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200, PASSING_VERDICT);
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertTrue(result.key().isEmpty());
        client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}},\"key\":null}");
        assertTrue(client.verify("{}", AttestOptions.of("n_1")).key().isEmpty());
    }

    @Test
    void verifyKeyAuthPolicyIsOptional() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}},"
                        + "\"key\":{\"keyId\":\"key_1\","
                        + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"eHg\",\"y\":\"eXk\"},"
                        + "\"purpose\":\"sign\",\"certifiedAt\":\"2030-01-01T00:01:00Z\"}}");
        CertifiedKey key = client.verify("{}", AttestOptions.of("n_1")).key().orElseThrow();
        assertNull(key.authPolicy());
    }

    @Test
    void verifyRejectsAMalformedKey() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}},\"key\":{\"keyId\":\"key_1\"}}");
        assertThrows(RootHeraldApiException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
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

    private static final String TPM_ENROLL_201 =
            "{\"enrollmentId\":\"enr-1\",\"credentialBlob\":\"cb==\",\"encryptedSecret\":\"es==\"}";

    @Test
    void relayEnrollSendsNoQueryString() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("windows")
                .build());
        assertNull(lastQuery.get());
    }

    @Test
    void typedEnrollBlobCarriesEverythingSetAndNothingElse() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("linux")
                .tpmSelfReport("IFX", "SLB9670")
                .build());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("IFX", sent.get("tpmSelfReport").get("manufacturer").asText());
        assertEquals("SLB9670", sent.get("tpmSelfReport").get("vendorString").asText());
        assertEquals(4, sent.size());
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
    void typedEnrollBlobRequiresThePlatformAndItsFields() {
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==").akPublicArea("akpub==").build());
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("ios").iosKeyId("k==").iosAttestationObject("att==").build());
        assertThrows(IllegalArgumentException.class, () -> EnrollRequestBlob.builder()
                .platform("windows").ekPublicKey("ekpub==").build());
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
    }

    @Test
    void relayEnrollRelaysAJsonBlobVerbatim() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201, TPM_ENROLL_201);
        client.relayEnroll("{\"ekPublicKey\":\"ekpub==\",\"akPublicArea\":\"akpub==\","
                + "\"platform\":\"linux\",\"tpmSelfReport\":{\"manufacturer\":\"IFX\","
                + "\"vendorString\":\"SLB9670\"}}");
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("linux", sent.get("platform").asText());
        assertEquals("IFX", sent.get("tpmSelfReport").get("manufacturer").asText());
        assertNull(lastQuery.get());
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
        assertThrows(RootHeraldApiException.class, () -> client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("windows")
                .build()));
    }

    @Test
    void relayEnrollRejectsA201WithoutEnrollmentIdOrProofMaterial() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 201,
                "{\"deviceId\":\"dev-1\",\"credentialBlob\":\"cb==\",\"encryptedSecret\":\"es==\"}");
        RootHeraldApiException ex = assertThrows(RootHeraldApiException.class,
                () -> client.relayEnroll(EnrollRequestBlob.builder()
                        .ekPublicKey("ekpub==").akPublicArea("akpub==").platform("windows").build()));
        assertTrue(ex.getMessage().contains("enrollmentId"));
        RootHeraldClient halfTpm = start("/api/v1/attest/enroll", 201,
                "{\"enrollmentId\":\"enr-1\",\"credentialBlob\":\"cb==\"}");
        assertThrows(RootHeraldApiException.class,
                () -> halfTpm.relayEnroll(EnrollRequestBlob.builder()
                        .ekPublicKey("ekpub==").akPublicArea("akpub==").platform("windows").build()));
    }

    @Test
    void relayEnrollRejectsABlobThatIsNotAJsonObject() {
        RootHeraldClient client = RootHeraldClient.builder().secretKey("rh_sk_test_xxx").build();
        assertThrows(RootHeraldException.class, () -> client.relayEnroll("not json"));
        assertThrows(RootHeraldException.class, () -> client.relayEnroll("[]"));
    }

    @Test
    void relayEnrollMaps422AdmissionRefused() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/enroll", 422,
                "{\"error\":\"admission_refused\",\"detail\":\"firmware TPM under a discrete-only policy\"}");
        AdmissionRefusedException ex = assertThrows(AdmissionRefusedException.class,
                () -> client.relayEnroll(EnrollRequestBlob.builder()
                        .ekPublicKey("ekpub==")
                        .akPublicArea("akpub==")
                        .platform("windows")
                        .build()));
        assertEquals("admission_refused", ex.errorCode());
        assertEquals("firmware TPM under a discrete-only policy", ex.getMessage());
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
        AttestResult result = client.verify("{\"quote\":\"...\"}",
                AttestOptions.of("n_1"));
        // A genuinely PASSING device (token at verdict.device.verdict) is a pass.
        assertEquals(Verdict.PASS, result.verdict());
        assertTrue(result.isPass());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("n_1", sent.get("nonce").asText());
        assertFalse(sent.has("challengeId"));
        assertEquals("...", sent.get("evidence").get("quote").asText());
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
    void aKeyBesideANonPassingVerdictIsPassedThrough() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"fail\"}},"
                        + "\"key\":{\"keyId\":\"key_1\","
                        + "\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"eHg\",\"y\":\"eXk\"},"
                        + "\"purpose\":\"sign\",\"certifiedAt\":\"2030-01-01T00:01:00Z\"}}");
        AttestResult result = client.verify("{}", AttestOptions.of("n_1"));
        assertEquals(Verdict.FAIL, result.verdict());
        assertEquals("key_1", result.key().orElseThrow().keyId());
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
    void maps429QuotaExceededByCodeOrHeader() throws Exception {
        RootHeraldClient client = start("/api/v1/attest/verify", 429,
                "{\"error\":\"quota_exceeded\",\"message\":\"ceiling\"}");
        assertThrows(QuotaExceededException.class,
                () -> client.verify("{}", AttestOptions.of("n_1")));
        RootHeraldClient byHeader = start("/api/v1/attest/verify", 429, "{}",
                "X-RootHerald-Quota", "device-limit-exceeded");
        assertThrows(QuotaExceededException.class,
                () -> byHeader.verify("{}", AttestOptions.of("n_1")));
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
        RelayEnrollResult result = client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("windows")
                .build());
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
        client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("linux")
                .ekCertPem("-----BEGIN CERT-----")
                .ekCertificateChain(List.of("int-a", "int-b"))
                .build());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("ekpub==", sent.get("ekPublicKey").asText());
        assertEquals("akpub==", sent.get("akPublicArea").asText());
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
                () -> client.relayEnroll(EnrollRequestBlob.builder()
                        .ekPublicKey("ekpub==")
                        .akPublicArea("akpub==")
                        .platform("windows")
                        .build()));
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

    @Test
    void enrollBlobRequiresEkAndAk() {
        assertThrows(IllegalArgumentException.class,
                () -> EnrollRequestBlob.builder().akPublicArea("akpub==").build());
        assertThrows(IllegalArgumentException.class,
                () -> EnrollRequestBlob.builder().ekPublicKey("ekpub==").build());
    }
}
