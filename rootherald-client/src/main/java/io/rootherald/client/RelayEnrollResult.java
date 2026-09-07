package io.rootherald.client;

import java.util.Objects;

/**
 * Result of the enroll relay leg
 * ({@link RootHeraldClient#relayEnroll(EnrollRequestBlob)}). Mirrors
 * {@code @rootherald/contracts}' {@code RelayEnrollResult}.
 *
 * <p>Enrolment always issues a challenge, including for a device already known —
 * re-enrolment is how a device rotates its attestation key, so short-circuiting
 * it would make rotation impossible. Relay {@link #challenge()} to the client's
 * {@code EnrollComplete}, then call
 * {@link RootHeraldClient#relayActivate(EnrollActivationResponse)}.
 *
 * <p>{@link #deviceId()} is THIS tenant's alias for the device, not a global
 * identifier: another tenant enrolling the same silicon is told a different one.
 */
public final class RelayEnrollResult {

    private final String deviceId;
    private final EnrollActivationChallenge challenge;
    private final String challengeId;

    private RelayEnrollResult(String deviceId, EnrollActivationChallenge challenge, String challengeId) {
        this.deviceId = deviceId;
        this.challenge = challenge;
        this.challengeId = challengeId;
    }

    /** An enroll carrying the MakeCredential challenge. */
    public static RelayEnrollResult fresh(String deviceId, EnrollActivationChallenge challenge) {
        return fresh(deviceId, challenge, null);
    }

    /** An enroll carrying the MakeCredential challenge, admitted against a challenge. */
    public static RelayEnrollResult fresh(String deviceId, EnrollActivationChallenge challenge,
                                          String challengeId) {
        Objects.requireNonNull(deviceId, "deviceId");
        Objects.requireNonNull(challenge, "challenge");
        return new RelayEnrollResult(deviceId, challenge, challengeId);
    }

    /** This tenant's alias for the device. */
    public String deviceId() {
        return deviceId;
    }

    /** The MakeCredential challenge to relay to the client. */
    public EnrollActivationChallenge challenge() {
        return challenge;
    }

    /**
     * The attestation challenge id this enrolment was admitted against, when
     * the server echoed one back; {@code null} otherwise.
     */
    public String challengeId() {
        return challengeId;
    }
}
