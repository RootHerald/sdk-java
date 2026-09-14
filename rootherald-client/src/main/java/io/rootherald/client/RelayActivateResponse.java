package io.rootherald.client;

/**
 * Response of the activate relay leg — {@code POST /api/v1/attest/activate}.
 * <p>
 * {@link #deviceId()} is the field the backend maps to its user;
 * {@code status}/{@code enrolledAt} are advisory. It is this tenant's alias for
 * the device, not a global identifier: another tenant enrolling the same
 * silicon is told a different one. It is for the backend only and must not be
 * relayed to the device.
 *
 * @param deviceId   this tenant's alias for the enrolled device
 * @param status     lifecycle status (e.g. {@code "enrolled"}), or {@code null}
 * @param enrolledAt ISO-8601 timestamp the device was enrolled, or {@code null}
 */
public record RelayActivateResponse(String deviceId, String status, String enrolledAt) {
}
