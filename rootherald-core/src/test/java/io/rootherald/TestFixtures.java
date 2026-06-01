package io.rootherald;

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
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Shared helpers for tests: build mock JWKS servers and sign sample tokens. */
public final class TestFixtures {

    private TestFixtures() {
    }

    public static RSAKey generateKey(String kid) throws Exception {
        return new RSAKeyGenerator(2048).keyID(kid).generate();
    }

    /**
     * Starts an in-process HTTP server that returns the supplied JWKSet at {@code /jwks}.
     * Returns a record holding the server, the bound URL, and a hit counter.
     */
    public static MockJwksServer startJwksServer(JWKSet jwks) throws IOException {
        return startJwksServer(jwks, null);
    }

    public static MockJwksServer startJwksServer(JWKSet jwks, String cacheControl) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger hits = new AtomicInteger();
        server.createContext("/jwks", exchange -> {
            hits.incrementAndGet();
            byte[] body = jwks.toString(true).getBytes(StandardCharsets.UTF_8);
            if (cacheControl != null) {
                exchange.getResponseHeaders().add("Cache-Control", cacheControl);
            }
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
        return signToken(key, claims, "JWT");
    }

    public static String signToken(RSAKey key, JWTClaimsSet claims, String typ) throws Exception {
        JOSEObjectType type = "JWT".equals(typ) ? JOSEObjectType.JWT : new JOSEObjectType(typ);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(type)
                .keyID(key.getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new RSASSASigner(key.toPrivateKey()));
        return jwt.serialize();
    }

    public static JWTClaimsSet sampleClaims(String issuer, String audience, String sub, Instant exp) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .subject(sub)
                .issueTime(Date.from(Instant.now()))
                .notBeforeTime(Date.from(Instant.now()))
                .expirationTime(Date.from(exp))
                .claim("eat_nonce", "bm9uY2U")
                .claim("eat_profile", "tag:rootherald.io,2026:tpm-passport")
                .claim("ueid", "ek-fingerprint-base64")
                .claim("hwmodel", "TestModel")
                .claim("dbgstat", "3")
                .claim("ear.status", 1)
                .build();
    }

    public static JWTClaimsSet sampleSetClaims(String issuer, String audience, String jti,
                                               String eventType, Map<String, Object> eventBody) {
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .jwtID(jti)
                .issueTime(Date.from(Instant.now()))
                .claim("events", Map.of(eventType, eventBody))
                .build();
    }

    public static List<String> audList(String aud) {
        return List.of(aud);
    }

    public record MockJwksServer(HttpServer server, String url, AtomicInteger hits) implements AutoCloseable {
        @Override
        public void close() {
            server.stop(0);
        }
    }
}
