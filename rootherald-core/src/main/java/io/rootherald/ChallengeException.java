package io.rootherald;

/**
 * The challenge or key challenge is unknown, expired, or already consumed
 * (HTTP 409). A 409 {@code key_rotation_conflict} is the base
 * {@link RootHeraldApiException} with the code preserved.
 */
public class ChallengeException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public ChallengeException(String message) {
        this(null, message);
    }

    public ChallengeException(String errorCode, String message) {
        super(409, errorCode, message);
    }
}
