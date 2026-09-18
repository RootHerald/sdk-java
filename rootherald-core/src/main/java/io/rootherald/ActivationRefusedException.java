package io.rootherald;

/**
 * {@code POST /api/v1/attest/activate} refused the enrollment (HTTP 401, code
 * {@code activation_refused}): the {@code enrollmentId} is unknown, spent or
 * foreign, or the proof did not match. The secret key was accepted; this is
 * not a credential problem. Every activation refusal reason produces this one
 * answer.
 */
public class ActivationRefusedException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public static final String ERROR_CODE = "activation_refused";

    public ActivationRefusedException(String message) {
        super(401, ERROR_CODE, message);
    }
}
