package io.rootherald;

/** The secret key was rejected by the RootHerald API (HTTP 401). */
public class InvalidSecretKeyException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public InvalidSecretKeyException(String message) {
        super(401, message);
    }
}
