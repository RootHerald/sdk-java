package io.rootherald.client;

/**
 * The {@code 201} body of {@code POST /api/v1/attest/enroll}, and the input to
 * the client's {@code EnrollComplete()}. Relay it to the client verbatim.
 * <p>
 * A TPM enrollment carries {@link #credentialBlob()} and
 * {@link #encryptedSecret()}, the {@code TPM2_MakeCredential} outputs fed
 * straight into the client's {@code TPM2_ActivateCredential}. A Secure Enclave
 * enrollment carries {@link #challengeNonce()}, which the enclave key signs.
 * Either way {@link #enrollmentId()} names the open enrollment and comes back
 * in the {@link EnrollActivationResponse}.
 *
 * @param enrollmentId    the server's id for this open enrollment (UUID)
 * @param credentialBlob  base64 {@code TPM2_MakeCredential} credential blob, or {@code null}
 * @param encryptedSecret base64 {@code TPM2_MakeCredential} encrypted secret, or {@code null}
 * @param challengeNonce  base64 nonce for the Secure Enclave key to sign, or {@code null}
 */
public record EnrollActivationChallenge(
        String enrollmentId, String credentialBlob, String encryptedSecret, String challengeNonce) {

    public EnrollActivationChallenge {
        if (enrollmentId == null || enrollmentId.isEmpty()) {
            throw new IllegalArgumentException("enrollmentId is required");
        }
        boolean tpm = notEmpty(credentialBlob) && notEmpty(encryptedSecret);
        if (!tpm && !notEmpty(challengeNonce)) {
            throw new IllegalArgumentException(
                    "credentialBlob and encryptedSecret, or challengeNonce, are required");
        }
    }

    private static boolean notEmpty(String s) {
        return s != null && !s.isEmpty();
    }
}
