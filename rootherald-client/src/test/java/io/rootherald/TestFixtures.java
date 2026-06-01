package io.rootherald;

// Re-export the core test fixtures via a tiny shim so the client tests can reuse them.
// In a real Maven build we'd publish a test-jar; this trampoline keeps the WIP simple.

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;

public final class TestFixtures {
    private TestFixtures() {}

    public static RSAKey generateKey(String kid) throws Exception {
        return new RSAKeyGenerator(2048).keyID(kid).generate();
    }

    public static MockJwksServer startJwksServer(JWKSet jwks) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger hits = new AtomicInteger();
        server.createContext("/jwks", exchange -> {
            hits.incrementAndGet();
            byte[] body = jwks.toString(true).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/jwk-set+json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
        return new MockJwksServer(server, url, hits);
    }

    public static String signToken(RSAKey key, JWTClaimsSet claims) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT).keyID(key.getKeyID()).build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(key.toPrivateKey()));
        return jwt.serialize();
    }

    public static JWTClaimsSet sampleClaims(String issuer, String aud, String sub, Instant exp) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer).audience(aud).subject(sub)
                .expirationTime(Date.from(exp))
                .notBeforeTime(Date.from(Instant.now()))
                .claim("eat_nonce", "bm9uY2U").build();
    }

    public record MockJwksServer(HttpServer server, String url, AtomicInteger hits) implements AutoCloseable {
        @Override
        public void close() { server.stop(0); }
    }
}
