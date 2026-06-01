package io.rootherald;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class JwksFetcherTest {

    @Test
    void fetchesAndReturnsKeyByKid() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        JWKSet set = new JWKSet(List.of(key.toPublicJWK()));
        try (var srv = TestFixtures.startJwksServer(set)) {
            JwksFetcher fetcher = new JwksFetcher(URI.create(srv.url()));
            JWK out = fetcher.getKey("k1");
            assertEquals("k1", out.getKeyID());
        }
    }

    @Test
    void cachesFetchAcrossCalls() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        JWKSet set = new JWKSet(List.of(key.toPublicJWK()));
        try (var srv = TestFixtures.startJwksServer(set, "max-age=3600")) {
            JwksFetcher fetcher = new JwksFetcher(URI.create(srv.url()));
            fetcher.getKey("k1");
            fetcher.getKey("k1");
            fetcher.getKey("k1");
            assertEquals(1, srv.hits().get(), "Cache-Control should prevent extra fetches");
        }
    }

    @Test
    void refreshAfterExplicitCall() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        JWKSet set = new JWKSet(List.of(key.toPublicJWK()));
        try (var srv = TestFixtures.startJwksServer(set, "max-age=3600")) {
            JwksFetcher fetcher = new JwksFetcher(URI.create(srv.url()));
            fetcher.refresh();
            fetcher.refresh();
            assertEquals(2, srv.hits().get());
        }
    }

    @Test
    void unknownKidThrows() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        JWKSet set = new JWKSet(List.of(key.toPublicJWK()));
        try (var srv = TestFixtures.startJwksServer(set)) {
            JwksFetcher fetcher = new JwksFetcher(URI.create(srv.url()));
            assertThrows(RootHeraldException.class, () -> fetcher.getKey("missing"));
        }
    }

    @Test
    void httpErrorThrows() {
        JwksFetcher fetcher = new JwksFetcher(URI.create("http://127.0.0.1:1/jwks"));
        assertThrows(RootHeraldException.class, () -> fetcher.getKey("any"));
    }

    @Test
    void parseMaxAgeAcceptsSeconds() {
        assertEquals(Optional.of(Duration.ofSeconds(120)), JwksFetcher.parseMaxAge("max-age=120"));
        assertEquals(Optional.of(Duration.ofSeconds(0)), JwksFetcher.parseMaxAge("max-age=0"));
    }

    @Test
    void parseMaxAgeAcceptsMixedDirectives() {
        assertEquals(Optional.of(Duration.ofSeconds(60)),
                JwksFetcher.parseMaxAge("public, max-age=60, must-revalidate"));
    }

    @Test
    void parseMaxAgeRejectsGarbage() {
        assertTrue(JwksFetcher.parseMaxAge(null).isEmpty());
        assertTrue(JwksFetcher.parseMaxAge("").isEmpty());
        assertTrue(JwksFetcher.parseMaxAge("no-cache").isEmpty());
        assertTrue(JwksFetcher.parseMaxAge("max-age=oops").isEmpty());
    }

    @Test
    void snapshotIsEmptyBeforeFirstFetch() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        JWKSet set = new JWKSet(List.of(key.toPublicJWK()));
        try (var srv = TestFixtures.startJwksServer(set)) {
            JwksFetcher fetcher = new JwksFetcher(URI.create(srv.url()));
            assertTrue(fetcher.snapshot().isEmpty());
            fetcher.refresh();
            assertTrue(fetcher.snapshot().isPresent());
        }
    }

    @Test
    void usesFallbackTtlWhenNoCacheControl() throws Exception {
        RSAKey key = TestFixtures.generateKey("k1");
        JWKSet set = new JWKSet(List.of(key.toPublicJWK()));
        try (var srv = TestFixtures.startJwksServer(set)) {
            AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-05-17T00:00:00Z"));
            Clock fixed = Clock.fixed(now.get(), ZoneOffset.UTC);
            JwksFetcher fetcher = new JwksFetcher(URI.create(srv.url()),
                    java.net.http.HttpClient.newHttpClient(), Duration.ofSeconds(5), fixed);
            fetcher.getKey("k1");
            fetcher.getKey("k1");
            assertEquals(1, srv.hits().get());
        }
    }
}
