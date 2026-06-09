package io.rootherald;

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

import java.net.URI;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies RootHerald attestation tokens issued by the platform's RATS verifier.
 * <p>
 * The verifier fetches the issuer's JWKS, resolves the signing key by {@code kid},
 * and checks signature + standard claims ({@code iss}, {@code aud}, {@code exp},
 * {@code nbf}). The set of acceptable signature algorithms is fixed to
 * {@code RS256}, {@code ES256}, {@code PS256} by default.
 *
 * <p>Use {@link #builder()} to construct one. Instances are thread-safe and
 * intended to be a long-lived singleton in the host application.</p>
 */
public final class AttestationTokenVerifier implements TokenVerifier {

    private static final Set<JWSAlgorithm> DEFAULT_ALGS = Set.of(
            JWSAlgorithm.RS256, JWSAlgorithm.ES256, JWSAlgorithm.PS256);

    private final String expectedIssuer;
    private final String expectedAudience;
    private final JwksFetcher jwks;
    private final Set<JWSAlgorithm> acceptedAlgs;
    private final Duration clockSkew;
    private final Clock clock;

    private AttestationTokenVerifier(Builder b) {
        this.expectedIssuer = Objects.requireNonNull(b.issuer, "issuer");
        this.expectedAudience = b.audience;
        this.jwks = Objects.requireNonNull(b.jwks, "jwksFetcher");
        this.acceptedAlgs = b.acceptedAlgs;
        this.clockSkew = b.clockSkew;
        this.clock = b.clock;
    }

    public static Builder builder() {
        return new Builder();
    }

    @Override
    public AttestationClaims verify(String token) {
        Objects.requireNonNull(token, "token");
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(token);
        } catch (ParseException ex) {
            throw new RootHeraldException("Malformed JWT: " + ex.getMessage(), ex);
        }

        JWSHeader header = jwt.getHeader();
        JWSAlgorithm alg = header.getAlgorithm();
        if (alg == null || !acceptedAlgs.contains(alg)) {
            throw new RootHeraldException("Unsupported JWS algorithm: " + alg);
        }
        String kid = header.getKeyID();
        if (kid == null || kid.isBlank()) {
            throw new RootHeraldException("JWS header missing 'kid'");
        }

        JWK key = jwks.getKey(kid);
        JWSVerifier verifier;
        try {
            if (key instanceof RSAKey rsa) {
                verifier = new RSASSAVerifier(rsa.toRSAPublicKey());
            } else if (key instanceof ECKey ec) {
                verifier = new ECDSAVerifier(ec.toECPublicKey());
            } else {
                throw new RootHeraldException("Unsupported JWK key type: " + key.getKeyType());
            }
        } catch (JOSEException ex) {
            throw new RootHeraldException("Failed to load verifier key: " + ex.getMessage(), ex);
        }

        boolean valid;
        try {
            valid = jwt.verify(verifier);
        } catch (JOSEException ex) {
            throw new RootHeraldException("Signature verification error: " + ex.getMessage(), ex);
        }
        if (!valid) {
            throw new RootHeraldException("JWT signature did not verify");
        }

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException ex) {
            throw new RootHeraldException("Malformed JWT claims: " + ex.getMessage(), ex);
        }

        if (!expectedIssuer.equals(claims.getIssuer())) {
            throw new RootHeraldException("Issuer mismatch: expected '" + expectedIssuer
                    + "', got '" + claims.getIssuer() + "'");
        }
        if (expectedAudience != null) {
            List<String> aud = claims.getAudience();
            if (aud == null || !aud.contains(expectedAudience)) {
                throw new RootHeraldException("Audience mismatch: expected '" + expectedAudience
                        + "', got " + aud);
            }
        }

        Instant now = clock.instant();
        Date exp = claims.getExpirationTime();
        if (exp == null) {
            throw new RootHeraldException("JWT missing 'exp' claim");
        }
        if (exp.toInstant().plus(clockSkew).isBefore(now)) {
            throw new TokenExpiredException("Token expired at " + exp.toInstant());
        }
        Date nbf = claims.getNotBeforeTime();
        if (nbf != null && nbf.toInstant().minus(clockSkew).isAfter(now)) {
            throw new RootHeraldException("Token not yet valid; nbf=" + nbf.toInstant());
        }

        return toAttestationClaims(claims);
    }

    private static AttestationClaims toAttestationClaims(JWTClaimsSet c) {
        // Defensive copy shared (read-only) as the forwards-compat map on both records.
        Map<String, Object> raw = new HashMap<>(c.getClaims());
        DeviceClaims device = new DeviceClaims(
                asString(raw.get("ueid")),
                asString(raw.get("hwmodel")),
                asString(raw.get("dbgstat")),
                asInteger(raw.get("ear.status")),
                raw
        );
        return new AttestationClaims(
                c.getSubject(),
                c.getIssuer(),
                c.getAudience(),
                toInstant(c.getExpirationTime()),
                toInstant(c.getIssueTime()),
                toInstant(c.getNotBeforeTime()),
                asString(raw.get("eat_nonce")),
                asString(raw.get("eat_profile")),
                device,
                raw
        );
    }

    private static Instant toInstant(Date date) {
        return date == null ? null : date.toInstant();
    }

    private static String asString(Object v) {
        return v == null ? null : v.toString();
    }

    private static Integer asInteger(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof Number n) {
            return n.intValue();
        }
        try {
            return Integer.parseInt(v.toString());
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    public static final class Builder {
        private String issuer;
        private String audience;
        private URI jwksUri;
        private JwksFetcher jwks;
        private Set<JWSAlgorithm> acceptedAlgs = DEFAULT_ALGS;
        private Duration clockSkew = Duration.ofSeconds(60);
        private Clock clock = Clock.systemUTC();

        public Builder issuer(String issuer) { this.issuer = issuer; return this; }
        public Builder audience(String audience) { this.audience = audience; return this; }
        public Builder jwksUri(String uri) { this.jwksUri = URI.create(uri); return this; }
        public Builder jwksUri(URI uri) { this.jwksUri = uri; return this; }
        public Builder jwksFetcher(JwksFetcher fetcher) { this.jwks = fetcher; return this; }
        public Builder acceptedAlgorithms(Set<JWSAlgorithm> algs) { this.acceptedAlgs = Set.copyOf(algs); return this; }
        public Builder clockSkew(Duration skew) { this.clockSkew = skew; return this; }
        public Builder clock(Clock clock) { this.clock = clock; return this; }

        public AttestationTokenVerifier build() {
            if (jwks == null) {
                if (jwksUri == null) {
                    throw new IllegalStateException("jwksUri or jwksFetcher is required");
                }
                jwks = new JwksFetcher(jwksUri);
            }
            return new AttestationTokenVerifier(this);
        }
    }
}
