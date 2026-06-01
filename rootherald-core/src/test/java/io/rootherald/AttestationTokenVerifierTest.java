package io.rootherald;

import com.nimbusds.jose.JOSEObjectType;
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

import static org.junit.jupiter.api.Assertions.*;

class AttestationTokenVerifierTest {

    private static AttestationTokenVerifier verifier(String url, String issuer, String audience) {
        return AttestationTokenVerifier.builder()
                .issuer(issuer)
                .audience(audience)
                .jwksFetcher(new JwksFetcher(URI.create(url)))
                .build();
    }

    @Test
    void verifiesValidToken() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(key,
                    TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                            Instant.now().plusSeconds(300)));
            AttestationClaims claims = verifier(srv.url(), "https://issuer.example", "rp-1").verify(token);
            assertEquals("device-1", claims.subject());
            assertEquals("https://issuer.example", claims.issuer());
            assertEquals("TestModel", claims.device().hwmodel());
            assertEquals(Integer.valueOf(1), claims.device().earStatus());
        }
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(key,
                    TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                            Instant.now().minusSeconds(600)));
            assertThrows(TokenExpiredException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify(token));
        }
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(key,
                    TestFixtures.sampleClaims("https://wrong.example", "rp-1", "device-1",
                            Instant.now().plusSeconds(300)));
            RootHeraldException ex = assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify(token));
            assertTrue(ex.getMessage().contains("Issuer mismatch"));
        }
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(key,
                    TestFixtures.sampleClaims("https://issuer.example", "rp-other", "device-1",
                            Instant.now().plusSeconds(300)));
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify(token));
        }
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(key,
                    TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                            Instant.now().plusSeconds(300)));
            String tampered = token.substring(0, token.length() - 4) + "AAAA";
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify(tampered));
        }
    }

    @Test
    void rejectsTokenSignedByWrongKey() throws Exception {
        RSAKey servedKey = TestFixtures.generateKey("k1");
        RSAKey attackerKey = TestFixtures.generateKey("k1"); // same kid, different material
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(servedKey.toPublicJWK())))) {
            String token = TestFixtures.signToken(attackerKey,
                    TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                            Instant.now().plusSeconds(300)));
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify(token));
        }
    }

    @Test
    void rejectsUnknownKid() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        RSAKey other = TestFixtures.generateKey("k2");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(other,
                    TestFixtures.sampleClaims("https://issuer.example", "rp-1", "device-1",
                            Instant.now().plusSeconds(300)));
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify(token));
        }
    }

    @Test
    void rejectsMalformedToken() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", "rp-1").verify("not.a.jwt"));
        }
    }

    @Test
    void allowsNullAudienceConfig() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            String token = TestFixtures.signToken(key,
                    TestFixtures.sampleClaims("https://issuer.example", "any-rp", "device-1",
                            Instant.now().plusSeconds(300)));
            assertNotNull(verifier(srv.url(), "https://issuer.example", null).verify(token));
        }
    }

    @Test
    void rejectsAlgNone() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            // Manually craft an "alg=none" style token (no signer); we just want the alg check to fire.
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT)
                    .keyID("k1")
                    .build();
            byte[] sharedSecret = new byte[32];
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer("https://issuer.example")
                    .subject("d1")
                    .expirationTime(Date.from(Instant.now().plusSeconds(60)))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new com.nimbusds.jose.crypto.MACSigner(sharedSecret));
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", null).verify(jwt.serialize()));
        }
    }

    @Test
    void rejectsTokenMissingKid() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        try (var srv = TestFixtures.startJwksServer(new JWKSet(List.of(key.toPublicJWK())))) {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
            SignedJWT jwt = new SignedJWT(header,
                    new JWTClaimsSet.Builder().issuer("https://issuer.example")
                            .expirationTime(Date.from(Instant.now().plusSeconds(60))).build());
            jwt.sign(new RSASSASigner(key.toPrivateKey()));
            assertThrows(RootHeraldException.class,
                    () -> verifier(srv.url(), "https://issuer.example", null).verify(jwt.serialize()));
        }
    }
}
