package io.rootherald;

/**
 * Thrown when a CAEP SET webhook cannot be verified — invalid signature,
 * tampered payload, unsupported algorithm, or missing key.
 */
public class WebhookSignatureException extends RootHeraldException {
    private static final long serialVersionUID = 1L;

    public WebhookSignatureException(String message) {
        super(message);
    }

    public WebhookSignatureException(String message, Throwable cause) {
        super(message, cause);
    }
}
