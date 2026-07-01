package io.rootherald;

/** The challenge is unknown, expired, or already consumed (HTTP 409). */
public class ChallengeException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public ChallengeException(String message) {
        super(409, message);
    }
}
