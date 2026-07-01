package io.rootherald.client;

/**
 * The {@code TPM2_MakeCredential} challenge — the {@code 201} response body of
 * {@code POST /api/v1/devices/enroll}, and the input to the client's
 * {@code EnrollComplete()}.
 * <p>
 * Mirrors {@code @rootherald/contracts}' {@code EnrollActivationChallenge}.
 * {@link #credentialBlob()} and {@link #encryptedSecret()} are fed straight into
 * the client's {@code TPM2_ActivateCredential}.
 *
 * @param deviceId        the deterministic device id (UUID), derived server-side from the EK
 * @param credentialBlob  base64 {@code TPM2_MakeCredential} credential blob
 * @param encryptedSecret base64 {@code TPM2_MakeCredential} encrypted secret
 */
public record EnrollActivationChallenge(String deviceId, String credentialBlob, String encryptedSecret) {
}
