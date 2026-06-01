package io.rootherald;

/**
 * Strategy interface for verifying RootHerald attestation tokens.
 * <p>
 * Implemented by {@link AttestationTokenVerifier} for production; framework
 * integrations (e.g. {@code rootherald-spring}) accept this type so tests can
 * inject deterministic fakes.
 */
public interface TokenVerifier {
    /**
     * Verify a compact-serialised JWT.
     *
     * @param token the attestation token string ({@code header.payload.signature})
     * @return decoded claims if every check passes
     * @throws TokenExpiredException  if {@code exp} is in the past (allowing for skew)
     * @throws RootHeraldException    for any other validation failure (signature,
     *                                issuer, audience, unknown kid, parse error, etc.)
     */
    AttestationClaims verify(String token);
}
