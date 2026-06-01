package io.rootherald;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Decoded RootHerald attestation token. Fields mirror the JWT claims emitted by the
 * RootHerald verifier service.
 *
 * @param subject        Device identifier ({@code sub})
 * @param issuer         Token issuer ({@code iss})
 * @param audience       Audience list ({@code aud}) — relying party client IDs
 * @param expiresAt      Expiration ({@code exp})
 * @param issuedAt       Issued-at ({@code iat}), may be null
 * @param notBefore      Not-before ({@code nbf}), may be null
 * @param nonce          Base64 challenge nonce ({@code eat_nonce})
 * @param eatProfile     EAT profile URN ({@code eat_profile})
 * @param device         Device-scoped claims
 * @param rawClaims      Full claim map for forwards compatibility
 */
public record AttestationClaims(
        String subject,
        String issuer,
        List<String> audience,
        Instant expiresAt,
        Instant issuedAt,
        Instant notBefore,
        String nonce,
        String eatProfile,
        DeviceClaims device,
        Map<String, Object> rawClaims
) {
}
