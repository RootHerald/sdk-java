package io.rootherald.client;

import java.util.Objects;
import java.util.Optional;

/**
 * Resolved result of the enroll relay leg
 * ({@link BackgroundCheckClient#relayEnroll(EnrollRequestBlob)}), normalizing the
 * asymmetric {@code 201}/{@code 409} HTTP outcomes of
 * {@code POST /api/v1/devices/enroll} into one shape so callers branch on
 * {@link #alreadyEnrolled()} instead of re-parsing HTTP status. Mirrors
 * {@code @rootherald/contracts}' {@code RelayEnrollResult} union.
 *
 * <ul>
 *   <li><b>{@code alreadyEnrolled() == false}</b> — fresh {@code 201} enroll:
 *       {@link #challenge()} is present; relay it to the client's
 *       {@code EnrollComplete}, then call
 *       {@link BackgroundCheckClient#relayActivate(EnrollActivationResponse)}.</li>
 *   <li><b>{@code alreadyEnrolled() == true}</b> — {@code 409} short-circuit: the
 *       device is already bound, so SKIP the activate leg and just use
 *       {@link #deviceId()}. No challenge.</li>
 * </ul>
 *
 * Either way {@link #deviceId()} is resolved.
 */
public final class RelayEnrollResult {

    private final boolean alreadyEnrolled;
    private final String deviceId;
    private final EnrollActivationChallenge challenge;

    private RelayEnrollResult(boolean alreadyEnrolled, String deviceId, EnrollActivationChallenge challenge) {
        this.alreadyEnrolled = alreadyEnrolled;
        this.deviceId = deviceId;
        this.challenge = challenge;
    }

    /** A fresh ({@code 201}) enroll carrying the MakeCredential challenge. */
    public static RelayEnrollResult fresh(String deviceId, EnrollActivationChallenge challenge) {
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(challenge, "challenge");
        return new RelayEnrollResult(false, deviceId, challenge);
    }

    /** An already-enrolled ({@code 409}) short-circuit; the activate leg is skipped. */
    public static RelayEnrollResult alreadyEnrolled(String deviceId) {
        Objects.requireNonNull(deviceId, "deviceId");
        return new RelayEnrollResult(true, deviceId, null);
    }

    /** Whether the device was already bound ({@code 409}); if so, skip activate. */
    public boolean alreadyEnrolled() {
        return alreadyEnrolled;
    }

    /** The resolved device id (UUID), present in both branches. */
    public String deviceId() {
        return deviceId;
    }

    /**
     * The MakeCredential challenge for a fresh enroll; empty when
     * {@link #alreadyEnrolled()} is {@code true}.
     */
    public Optional<EnrollActivationChallenge> challenge() {
        return Optional.ofNullable(challenge);
    }
}
