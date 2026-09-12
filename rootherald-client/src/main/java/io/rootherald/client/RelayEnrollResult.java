package io.rootherald.client;

import java.util.Objects;
import java.util.Optional;

/**
 * Result of the enroll relay leg
 * ({@link RootHeraldClient#relayEnroll(EnrollRequestBlob)}).
 *
 * <p>Enrollment always issues a challenge, including for a device already known —
 * re-enrollment is how a device rotates its attestation key, so short-circuiting
 * it would make rotation impossible. Relay {@link #challenge()} to the client's
 * {@code EnrollComplete}, then call
 * {@link RootHeraldClient#relayActivate(EnrollActivationResponse)}.
 *
 * <p>An App Attest ({@code platform: "ios"}) enrollment is the exception: it
 * completes in one leg, the server's {@code 201} body is empty and
 * {@link #challenge()} is absent. Nothing is relayed back to the device and
 * there is no activate leg.
 */
public final class RelayEnrollResult {

    private final EnrollActivationChallenge challenge;

    private RelayEnrollResult(EnrollActivationChallenge challenge) {
        this.challenge = challenge;
    }

    /** An enrollment carrying the challenge to relay to the client. */
    public static RelayEnrollResult of(EnrollActivationChallenge challenge) {
        return new RelayEnrollResult(Objects.requireNonNull(challenge, "challenge"));
    }

    /** A one-leg enrollment with nothing to relay back. */
    public static RelayEnrollResult withoutChallenge() {
        return new RelayEnrollResult(null);
    }

    /** The challenge to relay to the client's {@code EnrollComplete}, if this enrollment has a second leg. */
    public Optional<EnrollActivationChallenge> challenge() {
        return Optional.ofNullable(challenge);
    }
}
