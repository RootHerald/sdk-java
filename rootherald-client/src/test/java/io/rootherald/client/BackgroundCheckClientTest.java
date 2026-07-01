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

class BackgroundCheckClientTest {

    private HttpServer server;
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastAuth = new AtomicReference<>();
    private final ObjectMapper mapper = new ObjectMapper();

    @AfterEach
    void teardown() {
        if (server != null) server.stop(0);
    }

    private BackgroundCheckClient start(String path, int status, String responseJson) throws IOException {
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

    private BackgroundCheckClient startWith(String path, Consumer<HttpExchange> handler, String contextPath)
            throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(contextPath, handler::accept);
        server.start();
        return BackgroundCheckClient.builder()
                .secretKey("rh_sk_test_xxx")
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
                .build();
    }

    @Test
    void rejectsPublishableKey() {
        assertThrows(IllegalArgumentException.class,
                () -> BackgroundCheckClient.builder().secretKey("rh_pk_live_abc"));
    }

    @Test
    void rejectsEmptyKey() {
        assertThrows(IllegalArgumentException.class,
                () -> BackgroundCheckClient.builder().secretKey(""));
    }

    @Test
    void createChallengeSendsBearerSecret() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/challenge", 200,
                "{\"challengeId\":\"ch_1\",\"nonce\":\"n_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        Challenge challenge = client.createChallenge("device-hint");
        assertEquals("ch_1", challenge.challengeId());
        assertEquals("n_1", challenge.nonce());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void attestPassVerdictSurfacesToken() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"},\"token\":\"eyJ.signed.eat\"}");
        AttestResult result = client.attest("{\"quote\":\"...\"}",
                AttestOptions.of("ch_1").returnToken(true));
        assertTrue(result.isAllowed());
        assertEquals("eyJ.signed.eat", result.token());
        JsonNode sent = mapper.readTree(lastBody.get());
        assertEquals("ch_1", sent.get("challengeId").asText());
        assertEquals("...", sent.get("evidence").get("quote").asText());
    }

    @Test
    void exposesCohortFields() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\",\"device\":{"
                        + "\"cohortKey\":\"tpm20:win11:sb1:abc123\","
                        + "\"cohortScope\":\"tenant-fleet\","
                        + "\"cohortPrevalence\":0.042,"
                        + "\"cohortPrevalencePerPcr\":{\"0\":0.9,\"7\":0.5},"
                        + "\"cohortSampleSize\":1287,"
                        + "\"novelProfile\":false}}}");
        AttestResult result = client.attest("{}", AttestOptions.of("ch_1"));
        assertEquals("tpm20:win11:sb1:abc123", result.cohortKey());
        assertEquals("tenant-fleet", result.cohortScope());
        assertEquals(0.042, result.cohortPrevalence());
        assertEquals(0.5, result.cohortPrevalencePerPcr().get("7"));
        assertEquals(1287L, result.cohortSampleSize());
        assertEquals(Boolean.FALSE, result.novelProfile());
    }

    @Test
    void cohortFieldsNullWhenAbsent() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}");
        AttestResult result = client.attest("{}", AttestOptions.of("ch_1"));
        assertNull(result.cohortKey());
        assertNull(result.cohortPrevalence());
        assertNull(result.novelProfile());
        assertTrue(result.cohortPrevalencePerPcr().isEmpty());
    }

    @Test
    void failVerdictIsNotAnError() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"verdict\":\"fail\"}}");
        AttestResult result = client.attest("{}", AttestOptions.of("ch_1"));
        assertEquals("deny", result.verdict());
        assertNull(result.token());
    }

    @Test
    void maps401ToInvalidSecretKey() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 401,
                "{\"error\":\"x\",\"message\":\"boom\"}");
        assertThrows(InvalidSecretKeyException.class,
                () -> client.attest("{}", AttestOptions.of("ch_1")));
    }

    @Test
    void maps422ToUnknownPolicy() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 422,
                "{\"message\":\"no such policy\"}");
        assertThrows(UnknownPolicyException.class,
                () -> client.attest("{}", AttestOptions.of("ch_1").policy("nope")));
    }

    @Test
    void maps409ToChallenge() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 409, "{}");
        assertThrows(ChallengeException.class,
                () -> client.attest("{}", AttestOptions.of("ch_1")));
    }

    @Test
    void maps400ToInvalidEvidence() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 400, "{}");
        assertThrows(InvalidEvidenceException.class,
                () -> client.attest("{}", AttestOptions.of("ch_1")));
    }

    @Test
    void maps429ToQuotaExceeded() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 429, "{}");
        assertThrows(QuotaExceededException.class,
                () -> client.attest("{}", AttestOptions.of("ch_1")));
    }

    // ── ABI backend-relay contract ────────────────────────────────────────

    @Test
    void issueChallengeIsTheCanonicalName() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/challenge", 200,
                "{\"challengeId\":\"ch_1\",\"nonce\":\"n_1\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}");
        Challenge challenge = client.issueChallenge();
        assertEquals("ch_1", challenge.challengeId());
        assertEquals("Bearer rh_sk_test_xxx", lastAuth.get());
    }

    @Test
    void verifyIsTheCanonicalName() throws Exception {
        BackgroundCheckClient client = start("/api/v1/attestations/verify", 200,
                "{\"verdict\":{\"verdict\":\"pass\",\"ueid\":\"dev-9\"}}");
        AttestResult result = client.verify("{}", AttestOptions.of("ch_1"));
        assertTrue(result.isAllowed());
    }

    @Test
    void relayEnrollFreshReturnsChallenge() throws Exception {
        BackgroundCheckClient client = start("/api/v1/devices/enroll", 201,
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
        BackgroundCheckClient client = start("/api/v1/devices/enroll", 201,
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
        BackgroundCheckClient client = start("/api/v1/devices/enroll", 409,
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
        BackgroundCheckClient client = start("/api/v1/devices/enroll", 409, "{}");
        assertThrows(RootHeraldApiException.class,
                () -> client.relayEnroll(EnrollRequestBlob.builder()
                        .ekPublicKey("ekpub==")
                        .akPublicArea("akpub==")
                        .platform("windows")
                        .build()));
    }

    @Test
    void relayEnrollMapsAuthError() throws Exception {
        BackgroundCheckClient client = start("/api/v1/devices/enroll", 401,
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
        BackgroundCheckClient client = start("/api/v1/devices/activate", 200,
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
