package io.rootherald;

/**
 * Enrollment was refused because the device can never satisfy the identity
 * policy bound to the API key (pinned on the supplied challenge) — for example
 * a firmware TPM under a discrete-TPM-only policy (HTTP 422, code
 * {@code admission_refused}). The server names the TPM class in the message.
 */
public class AdmissionRefusedException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public static final String ERROR_CODE = "admission_refused";

    public AdmissionRefusedException(String message) {
        super(422, ERROR_CODE, message);
    }
}
