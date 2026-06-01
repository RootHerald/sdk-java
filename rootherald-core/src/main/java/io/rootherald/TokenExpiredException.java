package io.rootherald;

/**
 * Thrown when a RootHerald attestation token's {@code exp} claim is in the past
 * (allowing for the configured clock skew).
 */
public class TokenExpiredException extends RootHeraldException {
    private static final long serialVersionUID = 1L;

    public TokenExpiredException(String message) {
        super(message);
    }
}
