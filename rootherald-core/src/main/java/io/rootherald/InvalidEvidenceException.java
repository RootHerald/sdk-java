package io.rootherald;

/**
 * The submitted body was malformed or of a shape the server does not accept
 * (HTTP 400): unparseable evidence, a 7.0-shaped enroll body
 * ({@code wire_version_unsupported}), or an attestation key whose qualified
 * name does not match its parent ({@code invalid_enroll_shape}). An
 * un-enrolled / failing device is NOT this exception — that returns a verdict.
 * A 400 {@code invalid_ask} is {@link InvalidAskException}.
 */
public class InvalidEvidenceException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public InvalidEvidenceException(String message) {
        this(null, message);
    }

    public InvalidEvidenceException(String errorCode, String message) {
        super(400, errorCode, message);
    }
}
