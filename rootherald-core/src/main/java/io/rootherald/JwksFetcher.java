package io.rootherald;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Fetches and caches a JWKS document from a verifier endpoint.
 * <p>
 * Honors {@code Cache-Control: max-age=N} for refresh interval. If the upstream
 * does not return a directive, the fetcher falls back to {@link #defaultTtl}.
 * <p>
 * Thread-safe. The cache is refreshed lazily on the first {@link #getKey(String)}
 * call after the TTL elapses; if the refresh fails the previous JWKSet is reused
 * to avoid a denial-of-service when the verifier is briefly unreachable.
 */
public class JwksFetcher {
    private static final Pattern MAX_AGE = Pattern.compile("max-age\\s*=\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(15);
    private static final Duration MIN_RETRY = Duration.ofSeconds(10);

    private final URI jwksUri;
    private final HttpClient httpClient;
    private final Duration defaultTtl;
    private final Clock clock;

    private final AtomicReference<CacheEntry> cache = new AtomicReference<>();

    public JwksFetcher(URI jwksUri) {
        this(jwksUri, HttpClient.newHttpClient(), DEFAULT_TTL, Clock.systemUTC());
    }

    public JwksFetcher(URI jwksUri, HttpClient httpClient, Duration defaultTtl, Clock clock) {
        this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.defaultTtl = Objects.requireNonNull(defaultTtl, "defaultTtl");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Resolve a key by {@code kid}, refreshing the cache if it has expired.
     *
     * @throws RootHeraldException if the JWKS cannot be fetched or the kid is not present
     */
    public JWK getKey(String kid) {
        Objects.requireNonNull(kid, "kid");
        CacheEntry entry = currentEntry();
        JWK key = entry.set.getKeyByKeyId(kid);
        if (key != null) {
            return key;
        }
        // Force-refresh once in case the verifier rotated keys
        if (entry.lastRefreshed.plus(MIN_RETRY).isBefore(clock.instant())) {
            CacheEntry fresh = refresh();
            JWK refreshed = fresh.set.getKeyByKeyId(kid);
            if (refreshed != null) {
                return refreshed;
            }
        }
        throw new RootHeraldException("Unknown JWKS kid: " + kid);
    }

    /** Force a refresh (used by tests and during retry-after-rotation). */
    public JWKSet refresh() {
        CacheEntry entry = fetch();
        cache.set(entry);
        return entry.set;
    }

    /** Returns the cached JWKSet without forcing a refresh — for diagnostics. */
    public Optional<JWKSet> snapshot() {
        CacheEntry entry = cache.get();
        return Optional.ofNullable(entry).map(e -> e.set);
    }

    private CacheEntry currentEntry() {
        CacheEntry entry = cache.get();
        if (entry == null || clock.instant().isAfter(entry.expiresAt)) {
            try {
                return refreshOrFallback(entry);
            } catch (RootHeraldException ex) {
                if (entry != null) {
                    return entry; // tolerate transient upstream failure
                }
                throw ex;
            }
        }
        return entry;
    }

    private CacheEntry refreshOrFallback(CacheEntry previous) {
        try {
            return refreshInternal();
        } catch (RootHeraldException ex) {
            if (previous != null) {
                return previous;
            }
            throw ex;
        }
    }

    private CacheEntry refresh() {
        CacheEntry entry = refreshInternal();
        cache.set(entry);
        return entry;
    }

    private CacheEntry fetch() {
        return refreshInternal();
    }

    private CacheEntry refreshInternal() {
        HttpRequest request = HttpRequest.newBuilder(jwksUri)
                .header("Accept", "application/jwk-set+json, application/json")
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException ex) {
            throw new RootHeraldException("Failed to fetch JWKS: " + ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RootHeraldException("JWKS fetch interrupted", ex);
        }
        if (response.statusCode() / 100 != 2) {
            throw new RootHeraldException("JWKS endpoint returned HTTP " + response.statusCode());
        }
        JWKSet set;
        try {
            set = JWKSet.parse(response.body());
        } catch (ParseException ex) {
            throw new RootHeraldException("Malformed JWKS response: " + ex.getMessage(), ex);
        }
        Duration ttl = parseMaxAge(response.headers().firstValue("Cache-Control").orElse(""))
                .orElse(defaultTtl);
        Instant now = clock.instant();
        return new CacheEntry(set, now, now.plus(ttl));
    }

    static Optional<Duration> parseMaxAge(String cacheControl) {
        if (cacheControl == null || cacheControl.isBlank()) {
            return Optional.empty();
        }
        Matcher m = MAX_AGE.matcher(cacheControl.toLowerCase(Locale.ROOT));
        if (!m.find()) {
            return Optional.empty();
        }
        try {
            long seconds = Long.parseLong(m.group(1));
            if (seconds < 0) {
                return Optional.empty();
            }
            return Optional.of(Duration.ofSeconds(seconds));
        } catch (NumberFormatException ex) {
            return Optional.empty();
        }
    }

    private record CacheEntry(JWKSet set, Instant lastRefreshed, Instant expiresAt) {
    }
}
