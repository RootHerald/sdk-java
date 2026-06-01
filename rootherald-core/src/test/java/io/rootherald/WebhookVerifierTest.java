package io.rootherald;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WebhookVerifierTest {

    private static WebhookVerifier verifier(String url, String issuer, String aud) {
        return new WebhookVerifier(issuer, aud, new JwksFetcher(URI.create(url)));
    }

    @Test
    void verifiesValidSet() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String set = TestFixtures.signToken(key,
                    TestFixtures.sampleSetClaims("https://issuer.example", "tenant-1", "evt-1",
                            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
                            Map.of("subject_id", "device-1", "reason", "compromised")),
                    "secevent+jwt");
            var event = verifier(srv.url(), "https://issuer.example", "tenant-1").verify(set);
            assertEquals("evt-1", event.jti());
            assertTrue(event.events().has("https://schemas.openid.net/secevent/caep/event-type/session-revoked"));
        }
    }

    @Test
    void rejectsTamperedSet() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String set = TestFixtures.signToken(key,
                    TestFixtures.sampleSetClaims("https://issuer.example", "tenant-1", "evt-1",
                            "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
                            Map.of("subject_id", "device-1")),
                    "secevent+jwt");
            String tampered = set.substring(0, set.length() - 4) + "ZZZZ";
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(tampered));
        }
    }

    @Test
    void rejectsMissingSignature() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String body = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0."; // empty signature
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(body));
        }
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String set = TestFixtures.signToken(key,
                    TestFixtures.sampleSetClaims("https://other.example", "tenant-1", "evt-1",
                            "x", Map.of()),
                    "secevent+jwt");
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(set));
        }
    }

    @Test
    void rejectsWrongTyp() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String set = TestFixtures.signToken(key,
                    TestFixtures.sampleSetClaims("https://issuer.example", "tenant-1", "evt-1",
                            "x", Map.of()),
                    "JWT");
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(set));
        }
    }

    @Test
    void rejectsHs256Alg() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            byte[] sharedSecret = new byte[32];
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(new com.nimbusds.jose.JOSEObjectType("secevent+jwt"))
                    .keyID("k1")
                    .build();
            SignedJWT jwt = new SignedJWT(header,
                    TestFixtures.sampleSetClaims("https://issuer.example", "tenant-1", "evt-1", "x", Map.of()));
            jwt.sign(new com.nimbusds.jose.crypto.MACSigner(sharedSecret));
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(jwt.serialize()));
        }
    }

    @Test
    void rejectsMissingKid() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new com.nimbusds.jose.JOSEObjectType("secevent+jwt"))
                    .build();
            SignedJWT jwt = new SignedJWT(header,
                    TestFixtures.sampleSetClaims("https://issuer.example", "tenant-1", "evt-1", "x", Map.of()));
            jwt.sign(new RSASSASigner(key.toPrivateKey()));
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(jwt.serialize()));
        }
    }

    @Test
    void rejectsEmptyEvents() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            JWTClaimsSet c = new JWTClaimsSet.Builder()
                    .issuer("https://issuer.example")
                    .audience("tenant-1")
                    .jwtID("evt")
                    .issueTime(Date.from(Instant.now()))
                    .build();
            String set = TestFixtures.signToken(key, c, "secevent+jwt");
            assertThrows(WebhookSignatureException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "tenant-1").verify(set));
        }
    }
}
