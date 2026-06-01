package io.rootherald.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bind RootHerald settings from {@code application.yml} / {@code application.properties}.
 * <p>Example:
 * <pre>
 * rootherald:
 *   issuer: https://rootherald.io/myorg
 *   audience: my-app
 *   jwks-uri: https://rootherald.io/.well-known/jwks.json
 *   base-uri: https://rootherald.io
 *   api-key: ${ROOTHERALD_API_KEY}
 *   mode: offline   # or 'online'
 * </pre>
 */
@ConfigurationProperties(prefix = "rootherald")
public class RootHeraldProperties {
    /** Expected JWT issuer (REQUIRED). */
    private String issuer;
    /** Expected audience; null disables audience check. */
    private String audience;
    /** JWKS URL; if null, derived from {@code base-uri}. */
    private String jwksUri;
    /** Base URL of the RootHerald verifier (used by REST client). */
    private String baseUri = "https://rootherald.io";
    /** Optional API key for the verifier REST call. */
    private String apiKey;
    /** {@code offline} (local JWT check) or {@code online} (call verifier). */
    private String mode = "offline";

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }
    public String getAudience() { return audience; }
    public void setAudience(String audience) { this.audience = audience; }
    public String getJwksUri() { return jwksUri; }
    public void setJwksUri(String jwksUri) { this.jwksUri = jwksUri; }
    public String getBaseUri() { return baseUri; }
    public void setBaseUri(String baseUri) { this.baseUri = baseUri; }
    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }
}
