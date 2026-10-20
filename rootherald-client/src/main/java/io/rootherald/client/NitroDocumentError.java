package io.rootherald.client;

/**
 * The client SDK's report that it could not read the NitroTPM attestation
 * document, carried on an activate body as {@code nitroDocumentError} and
 * relayed as it is.
 *
 * @param stage         the step that failed
 * @param tpmRc         the TPM response code, an unsigned 32-bit value
 * @param responseShape a description of the response the client received
 */
public record NitroDocumentError(String stage, Long tpmRc, String responseShape) {
}
