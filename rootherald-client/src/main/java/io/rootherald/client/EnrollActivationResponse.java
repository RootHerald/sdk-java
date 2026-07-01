package io.rootherald.client;

/**
 * {@code EnrollComplete()} output — the body of {@code POST /api/v1/devices/activate}.
 * <p>
 * Produced by the keyless client (which decrypted the challenge inside the TPM)
 * and relayed by the backend via
 * {@link BackgroundCheckClient#relayActivate(EnrollActivationResponse)}. Mirrors
 * {@code @rootherald/contracts}' {@code EnrollActivationResponse}.
 *
 * @param deviceId        the {@code deviceId} from the {@link EnrollActivationChallenge} (required)
 * @param decryptedSecret base64 of the secret released by {@code TPM2_ActivateCredential}
 *                        — proof the AK is bound to the attested EK (required)
 * @param akPublicKey     optional base64 AK public area re-sent for the server's
 *                        anti key-substitution check, or {@code null}
 */
public record EnrollActivationResponse(String deviceId, String decryptedSecret, String akPublicKey) {

    public EnrollActivationResponse {
        if (deviceId == null || deviceId.isEmpty()) {
            throw new IllegalArgumentException("deviceId is required");
        }
        if (decryptedSecret == null || decryptedSecret.isEmpty()) {
            throw new IllegalArgumentException("decryptedSecret is required");
        }
    }

    /** Construct without the optional anti key-substitution AK public area. */
    public EnrollActivationResponse(String deviceId, String decryptedSecret) {
        this(deviceId, decryptedSecret, null);
    }
}
