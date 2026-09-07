package io.rootherald;

/** The challenge is unknown, expired, or already consumed (HTTP 409). */
public class ChallengeException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public ChallengeException(String message) {
        this(null, message);
    }

    public ChallengeException(String errorCode, String message) {
        super(409, errorCode, message);
    }
}
