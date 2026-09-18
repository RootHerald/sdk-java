package io.rootherald.client;

/**
 * The TPM's own, unsigned answer to {@code TPM2_GetCapability}, carried on a
 * TPM enroll body as {@code tpmSelfReport}. The server reads it only downward
 * — to recognise a software TPM that presents no EK certificate — never to
 * promote a device.
 *
 * @param manufacturer the TPM manufacturer id
 * @param vendorString the vendor string
 */
public record TpmSelfReport(String manufacturer, String vendorString) {
}
