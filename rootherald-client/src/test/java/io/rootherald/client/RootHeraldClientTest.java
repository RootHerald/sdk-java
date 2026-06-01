package io.rootherald.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import io.rootherald.AttestationClaims;
import io.rootherald.AttestationTokenVerifier;
import io.rootherald.JwksFetcher;
import io.rootherald.RootHeraldException;
import io.rootherald.TestFixtures;
import io.rootherald.TokenVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class RootHeraldClientTest {

    private HttpServer verifierServer;
    private TestFixtures.MockJwksServer jwksServer;
    private final AtomicReference<String> lastRequestBody = new AtomicReference<>();

    @AfterEach
    void teardown() {
        if (verifierServer != null) verifierServer.stop(0);
        if (jwksServer != null) jwksServer.close();
    }

    private RSAKey startServers(String verdict) throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        jwksServer = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())));
        verifierServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        verifierServer.createContext("/api/v1/verify", exchange -> {
            byte[] reqBytes = exchange.getRequestBody().readAllBytes();
            lastRequestBody.set(new String(reqBytes, StandardCharsets.UTF_8));
            String response = "{\"verdict\":\"" + verdict + "\",\"reason\":\"ok\",\"risk_score\":0.1}";
            byte[] body = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        verifierServer.start();
        return key;
    }

    private RootHeraldClient buildClient(RSAKey key) {
        TokenVerifier verifier = AttestationTokenVerifier.builder()
                .issuer("https://issuer.example")
                .audience("rp-1")
                .jwksFetcher(new JwksFetcher(URI.create(jwksServer.url())))
                .build();
        return RootHeraldClient.builder()
                .baseUri("http://127.0.0.1:" + verifierServer.getAddress().getPort())
                .issuer("https://issuer.example")
                .audience("rp-1")
                .verifier(verifier)
                .build();
    }

    @Test
    void offlineVerifyReturnsClaims() throws Exception {
        RSAKey key = startServers("allow");
        String token = TestFixtures.signToken(key,
                TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                        Instant.now().plusSeconds(300)));
        VerifyResult result = buildClient(key).verifyOffline(token);
        assertTrue(result.isAllowed());
        assertEquals("device-1", result.claims().subject());
    }

    @Test
    void onlineVerifyAllow() throws Exception {
        RSAKey key = startServers("allow");
        String token = TestFixtures.signToken(key,
                TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                        Instant.now().plusSeconds(300)));
        VerifyResult result = buildClient(key).verifyOnline(token, "signup");
        assertTrue(result.isAllowed());
        assertEquals(0.1, result.riskScore(), 0.0001);
        // Check request shape
        Map<?, ?> body = new ObjectMapper().readValue(lastRequestBody.get(), Map.class);
        assertEquals(token, body.get("token"));
        assertEquals("signup", body.get("action"));
    }

    @Test
    void onlineVerifyDenyReturnsNullClaims() throws Exception {
        RSAKey key = startServers("deny");
        String token = TestFixtures.signToken(key,
                TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                        Instant.now().plusSeconds(300)));
        VerifyResult result = buildClient(key).verifyOnline(token, "signup");
        assertFalse(result.isAllowed());
        assertNull(result.claims());
    }

    @Test
    void offlineVerifyRejectsExpired() throws Exception {
        RSAKey key = startServers("allow");
        String token = TestFixtures.signToken(key,
                TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                        Instant.now().minusSeconds(600)));
        assertThrows(RootHeraldException.class, () -> buildClient(key).verifyOffline(token));
    }

    @Test
    void onlineVerifyHandlesHttp401() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        jwksServer = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())));
        verifierServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        verifierServer.createContext("/api/v1/verify", exchange -> {
            byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(401, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        verifierServer.start();
        String token = TestFixtures.signToken(key,
                TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                        Instant.now().plusSeconds(300)));
        VerifyResult result = buildClient(key).verifyOnline(token, "signup");
        assertEquals("deny", result.verdict());
    }
}
