package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.rootherald.AttestationTokenVerifier;
import io.rootherald.JwksFetcher;
import io.rootherald.RootHeraldException;
import io.rootherald.TokenVerifier;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * High-level REST client for the RootHerald verifier service.
 * <p>
 * This is the badge-tier (offline verify) client. For the server -&gt; server
 * appraisal of a client-collected evidence blob, use
 * {@link BackgroundCheckClient} instead.
 * <ul>
 *   <li>{@link #verifyOffline(String)} — verifies the JWT locally using the cached JWKS.
 *       No network call once the JWKS is warmed up; suitable for hot signup paths.</li>
 *   <li>{@link #verifyOnline(String, String)} — DEPRECATED: targets a self-hosted
 *       {@code /api/v1/verify} service that does not exist on the stock RootHerald
 *       deployment. Use {@link BackgroundCheckClient} for server -&gt; server
 *       appraisal, or {@link #verifyOffline(String)} for badge checks.</li>
 * </ul>
 */
public final class RootHeraldClient {

    private final URI baseUri;
    private final String apiKey;
    private final HttpClient http;
    private final ObjectMapper mapper;
    private final TokenVerifier verifier;

    private RootHeraldClient(Builder b) {
        this.baseUri = Objects.requireNonNull(b.baseUri, "baseUri");
        this.apiKey = b.apiKey;
        this.http = b.httpClient != null ? b.httpClient
                : HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
        this.mapper = new ObjectMapper();
        this.verifier = b.verifier != null ? b.verifier : AttestationTokenVerifier.builder()
                .issuer(Objects.requireNonNull(b.issuer, "issuer"))
                .audience(b.audience)
                .jwksFetcher(new JwksFetcher(b.jwksUri != null
                        ? b.jwksUri
                        : baseUri.resolve("/.well-known/jwks.json")))
                .build();
    }

    public static Builder builder() { return new Builder(); }

    /** Verify locally using the cached JWKS. */
    public VerifyResult verifyOffline(String token) {
        var claims = verifier.verify(token);
        return new VerifyResult("allow", "offline-verified", -1.0, claims);
    }

    /**
     * POST the token to the verifier endpoint and return the verdict.
     *
     * @deprecated targets a self-hosted {@code /api/v1/verify} service absent on
     *     the stock RootHerald deployment. Use {@link BackgroundCheckClient} for
     *     server -&gt; server appraisal, or {@link #verifyOffline(String)} for
     *     badge-tier checks.
     */
    @Deprecated
    public VerifyResult verifyOnline(String token, String action) {
        Objects.requireNonNull(token, "token");
        URI endpoint = baseUri.resolve("/api/v1/verify");
        String body;
        try {
            body = mapper.writeValueAsString(Map.of(
                    "token", token,
                    "action", action == null ? "verify" : action
            ));
        } catch (Exception ex) {
            throw new RootHeraldException("Failed to serialise request: " + ex.getMessage(), ex);
        }

        HttpRequest.Builder req = HttpRequest.newBuilder(endpoint)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (apiKey != null) {
            req.header("Authorization", "Bearer " + apiKey);
        }

        HttpResponse<String> resp;
        try {
            resp = http.send(req.build(), HttpResponse.BodyHandlers.ofString());
        } catch (IOException ex) {
            throw new RootHeraldException("Verifier unreachable: " + ex.getMessage(), ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new RootHeraldException("Verifier call interrupted", ex);
        }

        if (resp.statusCode() == 401 || resp.statusCode() == 403) {
            return new VerifyResult("deny", "http-" + resp.statusCode(), -1.0, null);
        }
        if (resp.statusCode() / 100 != 2) {
            throw new RootHeraldException("Verifier returned HTTP " + resp.statusCode() + ": " + resp.body());
        }

        JsonNode tree;
        try {
            tree = mapper.readTree(resp.body());
        } catch (IOException ex) {
            throw new RootHeraldException("Malformed verifier response: " + ex.getMessage(), ex);
        }
        String verdict = tree.path("verdict").asText("allow");
        String reason = tree.path("reason").asText("");
        double score = tree.path("risk_score").asDouble(-1.0);
        // The server may also return the parsed claims; fall back to local parse to avoid duplication.
        var claims = verdict.equalsIgnoreCase("deny") ? null : verifier.verify(token);
        return new VerifyResult(verdict, reason, score, claims);
    }

    public TokenVerifier verifier() {
        return verifier;
    }

    public static final class Builder {
        private URI baseUri;
        private URI jwksUri;
        private String issuer;
        private String audience;
        private String apiKey;
        private HttpClient httpClient;
        private TokenVerifier verifier;

        public Builder baseUri(String uri) { this.baseUri = URI.create(uri); return this; }
        public Builder baseUri(URI uri) { this.baseUri = uri; return this; }
        public Builder jwksUri(String uri) { this.jwksUri = URI.create(uri); return this; }
        public Builder issuer(String issuer) { this.issuer = issuer; return this; }
        public Builder audience(String aud) { this.audience = aud; return this; }
        public Builder apiKey(String key) { this.apiKey = key; return this; }
        public Builder httpClient(HttpClient client) { this.httpClient = client; return this; }
        public Builder verifier(TokenVerifier v) { this.verifier = v; return this; }

        public RootHeraldClient build() {
            return new RootHeraldClient(this);
        }
    }
}
