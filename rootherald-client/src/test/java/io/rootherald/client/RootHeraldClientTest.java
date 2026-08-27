package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.rootherald.ChallengeException;
import io.rootherald.InvalidEvidenceException;
import io.rootherald.InvalidSecretKeyException;
import io.rootherald.QuotaExceededException;
import io.rootherald.RootHeraldApiException;
import io.rootherald.UnknownPolicyException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

class RootHeraldClientTest {

    private HttpServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();
    private final ObjectMapper mapper = new ObjectMapper();

    @AfterEach
    void teardown() {
        if (server != null) server.stop(0);
    }

    private RootHeraldClient start(String path, int status, String responseJson) throws IOException {
        return startWith(path, exchange -> {
            try {
                lastAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
                lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                byte[] body = responseJson.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
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
        RootHeraldClient client = start("/api/v1/attestations/challenge", 200,
                "{\"challengeId\":\"ch_1\",\"nonce\":\"n_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        Challenge challenge = client.issueChallenge("device-hint");
        assertEquals("ch_1", challenge.challengeId());
        assertEquals("n_1", challenge.nonce());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
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
        RootHeraldClient client = start("/api/v1/attestations/verify", 200, PASSING_VERDICT);
        AttestResult result = client.verify("{\"quote\":\"...\"}",
                AttestOptions.of("ch_1"));
        // A genuinely PASSING device (token at verdict.device.verdict) maps to allow.
        assertEquals("allow", result.verdict());
        assertTrue(result.isAllowed());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("ch_1", sent.get("challengeId").asText());
        assertEquals("...", sent.get("evidence").get("quote").asText());
    }

    @Test
    void exposesTopLevelParityFields() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200, PASSING_VERDICT);
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertEquals(List.of("urn:rootherald:assurance:hardware-backed"),
                result.assuranceClaimsMet());
        assertFalse(result.enrollmentRequired());
    }

    @Test
    void surfacesEnrollmentRequiredSignal() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"fail\"}},"
                        + "\"assuranceClaimsMet\":[],\"enrollmentRequired\":true}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertTrue(result.enrollmentRequired());
        assertTrue(result.assuranceClaimsMet().isEmpty());
        assertEquals("deny", result.verdict());
    }

    @Test
    void parityFieldsDefaultWhenAbsent() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertTrue(result.assuranceClaimsMet().isEmpty());
        assertFalse(result.enrollmentRequired());
    }

    @Test
    void sendsRequestedDisclosureClassWhenSet() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200, PASSING_VERDICT);
        client.verify("{}", AttestOptions.of("ch_1").requestedDisclosureClass("pseudonymous"));
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("pseudonymous", sent.get("requestedDisclosureClass").asText());
    }

    @Test
    void omitsRequestedDisclosureClassWhenUnset() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200, PASSING_VERDICT);
        client.verify("{}", AttestOptions.of("ch_1"));
        JsonNode sent = mapper.readTree(lastBody.get());
        assertFalse(sent.has("requestedDisclosureClass"));
    }

    @Test
    void exposesCohortFields() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"device\":{"
                        + "\"verdict\":\"pass\",\"ueid\":\"dev-9\","
                        + "\"cohortKey\":\"tpm20:win11:sb1:abc123\","
                        + "\"cohortScope\":\"tenant-fleet\","
                        + "\"cohortPrevalence\":0.042,"
                        + "\"cohortPrevalencePerPcr\":{\"0\":0.9,\"7\":0.5},"
                        + "\"cohortSampleSize\":1287,"
                        + "\"novelProfile\":false}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertEquals("tpm20:win11:sb1:abc123", result.cohortKey());
        assertEquals("tenant-fleet", result.cohortScope());
        assertEquals(0.042, result.cohortPrevalence());
        assertEquals(0.5, result.cohortPrevalencePerPcr().get("7"));
        assertEquals(1287L, result.cohortSampleSize());
        assertEquals(Boolean.FALSE, result.novelProfile());
    }

    @Test
    void cohortFieldsNullWhenAbsent() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertNull(result.cohortKey());
        assertNull(result.cohortPrevalence());
        assertNull(result.novelProfile());
        assertTrue(result.cohortPrevalencePerPcr().isEmpty());
    }

    @Test
    void failVerdictIsNotAnError() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"fail\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertEquals("deny", result.verdict());
    }

    @Test
    void maps401ToInvalidSecretKey() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 401,
                "{\"error\":\"x\",\"message\":\"boom\"}");
        assertThrows(InvalidSecretKeyException.class,
                () -> client.verify("{}", AttestOptions.of("ch_1")));
    }

    @Test
    void maps422ToUnknownPolicy() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 422,
                "{\"message\":\"no such policy\"}");
        assertThrows(UnknownPolicyException.class,
                () -> client.verify("{}", AttestOptions.of("ch_1").policy("nope")));
    }

    @Test
    void maps409ToChallenge() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 409, "{}");
        assertThrows(ChallengeException.class,
                () -> client.verify("{}", AttestOptions.of("ch_1")));
    }

    @Test
    void maps400ToInvalidEvidence() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 400, "{}");
        assertThrows(InvalidEvidenceException.class,
                () -> client.verify("{}", AttestOptions.of("ch_1")));
    }

    @Test
    void maps429ToQuotaExceeded() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 429, "{}");
        assertThrows(QuotaExceededException.class,
                () -> client.verify("{}", AttestOptions.of("ch_1")));
    }

    // ── ABI backend-relay contract ────────────────────────────────────────

    @Test
    void issueChallengeIsTheCanonicalName() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/challenge", 200,
                "{\"challengeId\":\"ch_1\",\"nonce\":\"n_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        Challenge challenge = client.issueChallenge();
        assertEquals("ch_1", challenge.challengeId());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void verifyIsTheCanonicalName() throws Exception {
        RootHeraldClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"device\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertTrue(result.isAllowed());
    }

    @Test
    void relayEnrollFreshReturnsChallenge() throws Exception {
        RootHeraldClient client = start("/api/v1/devices/enroll", 201,
                "{\"deviceId\":\"dev-1\",\"credentialBlob\":\"cb==\",\"encryptedSecret\":\"es==\"}");
        RelayEnrollResult result = client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("windows")
                .build());
        assertFalse(result.alreadyEnrolled());
        assertEquals("dev-1", result.deviceId());
        assertTrue(result.challenge().isPresent());
        assertEquals("cb==", result.challenge().get().credentialBlob());
        assertEquals("es==", result.challenge().get().encryptedSecret());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void relayEnrollSendsCanonicalWireShape() throws Exception {
        RootHeraldClient client = start("/api/v1/devices/enroll", 201,
                "{\"deviceId\":\"dev-1\",\"credentialBlob\":\"cb==\",\"encryptedSecret\":\"es==\"}");
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
    void relayEnrollAlreadyEnrolledSkipsActivate() throws Exception {
        RootHeraldClient client = start("/api/v1/devices/enroll", 409,
                "{\"deviceId\":\"dev-7\"}");
        RelayEnrollResult result = client.relayEnroll(EnrollRequestBlob.builder()
                .ekPublicKey("ekpub==")
                .akPublicArea("akpub==")
                .platform("windows")
                .build());
        assertTrue(result.alreadyEnrolled());
        assertEquals("dev-7", result.deviceId());
        assertTrue(result.challenge().isEmpty());
    }

    @Test
    void relayEnroll409MissingDeviceIdThrows() throws Exception {
        RootHeraldClient client = start("/api/v1/devices/enroll", 409, "{}");
        assertThrows(RootHeraldApiException.class,
                () -> client.relayEnroll(EnrollRequestBlob.builder()
                        .ekPublicKey("ekpub==")
                        .akPublicArea("akpub==")
                        .platform("windows")
                        .build()));
    }

    @Test
    void relayEnrollMapsAuthError() throws Exception {
        RootHeraldClient client = start("/api/v1/devices/enroll", 401,
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
        RootHeraldClient client = start("/api/v1/devices/activate", 200,
                "{\"deviceId\":\"dev-1\",\"status\":\"enrolled\",\"enrolledAt\":\"2030-01-01T00:00:00Z\"}");
        RelayActivateResponse result = client.relayActivate(
                new EnrollActivationResponse("dev-1", "secret=="));
        assertEquals("dev-1", result.deviceId());
        assertEquals("enrolled", result.status());
        assertEquals("2030-01-01T00:00:00Z", result.enrolledAt());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("dev-1", sent.get("deviceId").asText());
        assertEquals("secret==", sent.get("decryptedSecret").asText());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void relayActivateRequiresDeviceIdAndSecret() {
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationResponse("", "secret=="));
        assertThrows(IllegalArgumentException.class,
                () -> new EnrollActivationResponse("dev-1", ""));
    }

    @Test
    void enrollBlobRequiresEkAndAk() {
        assertThrows(IllegalArgumentException.class,
                () -> EnrollRequestBlob.builder().akPublicArea("akpub==").build());
        assertThrows(IllegalArgumentException.class,
                () -> EnrollRequestBlob.builder().ekPublicKey("ekpub==").build());
    }
}
