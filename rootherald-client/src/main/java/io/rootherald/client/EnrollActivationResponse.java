package io.rootherald.client;

/**
 * {@code EnrollComplete()} output — the body of {@code POST /api/v1/attest/activate}.
 * <p>
 * Produced by the keyless client and relayed by the backend via
 * {@link RootHeraldClient#relayActivate(EnrollActivationResponse)}. A TPM
 * carries the secret it released from the credential; a Secure Enclave carries
 * a signature over the challenge nonce. The server decides which proof to
 * demand from the platform recorded at enrollment, not from the body.
 *
 * @param enrollmentId    the {@code enrollmentId} from the {@link EnrollActivationChallenge} (required)
 * @param decryptedSecret base64 of the secret released by {@code TPM2_ActivateCredential}, or {@code null}
 * @param signature       base64 ECDSA-P256-SHA256 signature over {@code challengeNonce}
 *                        (DER or IEEE-P1363), or {@code null}
 */
public record EnrollActivationResponse(String enrollmentId, String decryptedSecret, String signature) {

    public EnrollActivationResponse {
        if (enrollmentId == null || enrollmentId.isEmpty()) {
            throw new IllegalArgumentException("enrollmentId is required");
        }
        boolean secret = decryptedSecret != null && !decryptedSecret.isEmpty();
        boolean signed = signature != null && !signature.isEmpty();
        if (secret == signed) {
            throw new IllegalArgumentException("exactly one of decryptedSecret or signature is required");
        }
    }

    /** A TPM's answer: the secret it released from the credential. */
    public static EnrollActivationResponse ofDecryptedSecret(String enrollmentId, String decryptedSecret) {
        return new EnrollActivationResponse(enrollmentId, decryptedSecret, null);
    }

    /** A Secure Enclave's answer: its signature over the challenge nonce. */
    public static EnrollActivationResponse ofSignature(String enrollmentId, String signature) {
        return new EnrollActivationResponse(enrollmentId, null, signature);
    }
}
