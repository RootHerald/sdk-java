package io.rootherald.client;

/**
 * Response of the activate relay leg — {@code POST /api/v1/devices/activate}.
 * <p>
 * Mirrors {@code @rootherald/contracts}' {@code RelayActivateResponse}. The
 * migration contract treats {@link #deviceId()} as the load-bearing field the
 * backend maps to its user; {@code status}/{@code enrolledAt} are advisory.
 *
 * @param deviceId   the enrolled device id (UUID)
 * @param status     lifecycle status (e.g. {@code "enrolled"}), or {@code null}
 * @param enrolledAt ISO-8601 timestamp the device was enrolled, or {@code null}
 */
public record RelayActivateResponse(String deviceId, String status, String enrolledAt) {
}
