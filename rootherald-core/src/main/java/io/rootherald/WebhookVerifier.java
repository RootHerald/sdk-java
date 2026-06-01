package io.rootherald;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies CAEP (Continuous Access Evaluation Protocol, RFC 8417) Security Event Tokens
 * delivered by the RootHerald webhook channel.
 * <p>
 * SETs are JWTs with the {@code typ} header set to {@code secevent+jwt} and an
 * {@code events} claim mapping event type URIs to event payloads.
 */
public final class WebhookVerifier {

    private static final Set<JWSAlgorithm> ACCEPTED = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.ES256, JWSAlgorithm.PS256);
    private static final String SET_TYP = "secevent+jwt";

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JwksFetcher jwks;
    private final ObjectMapper mapper = new ObjectMapper();

    public WebhookVerifier(String expectedIssuer, String expectedAudience, JwksFetcher jwks) {
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer, "expectedIssuer");
        this.expectedAudience = expectedAudience;
        this.jwks = Objects.requireNonNull(jwks, "jwks");
    }

    /**
     * Verify a SET JWT, returning a parsed view of the event payload.
     *
     * @param setJwt compact-serialised SET JWT
     * @return a {@link WebhookEvent} containing the SET metadata and events map
     * @throws WebhookSignatureException for any verification failure
     */
    public WebhookEvent verify(String setJwt) {
        Objects.requireNonNull(setJwt, "setJwt");
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(setJwt);
        } catch (ParseException ex) {
            throw new WebhookSignatureException("Malformed SET JWT: " + ex.getMessage(), ex);
        }

        JWSHeader header = jwt.getHeader();
        if (header.getAlgorithm() == null || !ACCEPTED.contains(header.getAlgorithm())) {
            throw new WebhookSignatureException("Unsupported SET algorithm: " + header.getAlgorithm());
        }
        if (header.getType() == null || !SET_TYP.equals(header.getType().getType())) {
            throw new WebhookSignatureException("SET header 'typ' must be '" + SET_TYP + "', got " + header.getType());
        }
        String kid = header.getKeyID();
        if (kid == null || kid.isBlank()) {
            throw new WebhookSignatureException("SET header missing 'kid'");
        }

        JWK key;
        try {
            key = jwks.getKey(kid);
        } catch (RootHeraldException ex) {
            throw new WebhookSignatureException(ex.getMessage(), ex);
        }

        JWSVerifier verifier;
        try {
            if (key instanceof RSAKey rsa) {
                verifier = new RSASSAVerifier(rsa.toRSAPublicKey());
            } else if (key instanceof ECKey ec) {
                verifier = new ECDSAVerifier(ec.toECPublicKey());
            } else {
                throw new WebhookSignatureException("Unsupported JWK type: " + key.getKeyType());
            }
            if (!jwt.verify(verifier)) {
                throw new WebhookSignatureException("SET signature did not verify");
            }
        } catch (JOSEException ex) {
            throw new WebhookSignatureException("SET signature error: " + ex.getMessage(), ex);
        }

        JWTClaimsSet c;
        try {
            c = jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new WebhookSignatureException("Malformed SET claims: " + ex.getMessage(), ex);
        }
        if (!expectedIssuer.equals(c.getIssuer())) {
            throw new WebhookSignatureException("SET issuer mismatch: expected '" + expectedIssuer
                    + "', got '" + c.getIssuer() + "'");
        }
        if (expectedAudience != null) {
            var aud = c.getAudience();
            if (aud == null || !aud.contains(expectedAudience)) {
                throw new WebhookSignatureException("SET audience mismatch: expected '"
                        + expectedAudience + "', got " + aud);
            }
        }

        Object events = c.getClaim("events");
        if (!(events instanceof Map<?, ?> eventsMap) || eventsMap.isEmpty()) {
            throw new WebhookSignatureException("SET missing or empty 'events' claim");
        }

        JsonNode tree;
        try {
            tree = mapper.valueToTree(eventsMap);
        } catch (IllegalArgumentException ex) {
            throw new WebhookSignatureException("SET events not serialisable: " + ex.getMessage(), ex);
        }
        return new WebhookEvent(c.getJWTID(), c.getIssuer(), c.getAudience(),
                c.getIssueTime() != null ? c.getIssueTime().toInstant() : null,
                c.getSubject(), tree);
    }

    /**
     * Decoded CAEP Security Event Token payload.
     *
     * @param jti         unique event identifier
     * @param issuer      token issuer
     * @param audience    audience list
     * @param issuedAt    issued-at instant (may be null)
     * @param subject     event subject identifier (may be null; SETs may use the inner sub_id)
     * @param events      raw JSON tree of {@code events} claim
     */
    public record WebhookEvent(
            String jti,
            String issuer,
            java.util.List<String> audience,
            java.time.Instant issuedAt,
            String subject,
            JsonNode events
    ) {
    }
}
