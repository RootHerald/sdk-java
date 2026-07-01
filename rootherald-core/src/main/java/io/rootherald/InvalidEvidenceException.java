package io.rootherald;

/**
 * The submitted evidence blob was malformed or unparseable (HTTP 400). An
 * un-enrolled / failing device is NOT this exception — that returns a verdict.
 */
public class InvalidEvidenceException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public InvalidEvidenceException(String message) {
        super(400, message);
    }
}
