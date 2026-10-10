package io.rootherald.client;

/**
 * The per-installation attestation key, as the client's {@code EnrollBegin()}
 * describes it on a TPM enroll body ({@code attestationKey}). All three
 * fields base64.
 * <p>
 * The server recomputes the qualified name from the two public areas and
 * refuses the enrollment ({@code 400 invalid_enroll_shape}) when it differs
 * from {@code qualifiedName}, so a key created under the wrong parent fails
 * before any elevation prompt and before any row is written.
 *
 * @param publicArea       {@code TPM2B_PUBLIC} of the AK, as {@code TPM2_Create} emitted it
 * @param parentPublicArea {@code TPM2B_PUBLIC} of the storage parent the AK was created under
 * @param qualifiedName    {@code TPM2B_NAME} qualified name of the AK, as {@code TPM2_ReadPublic} returned it
 */
public record AttestationKey(String publicArea, String parentPublicArea, String qualifiedName) {

    public AttestationKey {
        requireText(publicArea, "attestationKey.publicArea");
        requireText(parentPublicArea, "attestationKey.parentPublicArea");
        requireText(qualifiedName, "attestationKey.qualifiedName");
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }
}
