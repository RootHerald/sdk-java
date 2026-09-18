package io.rootherald;

/**
 * The secret key was rejected by the RootHerald API (HTTP 401). A 401 carrying
 * {@code activation_refused} is {@link ActivationRefusedException} instead.
 */
public class InvalidSecretKeyException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public InvalidSecretKeyException(String message) {
        this(null, message);
    }

    public InvalidSecretKeyException(String errorCode, String message) {
        super(401, errorCode, message);
    }
}
