package io.rootherald.client;

import java.util.List;

/**
 * Options for {@link RootHeraldClient#issueKeyChallenge(KeyChallengeOptions)}.
 * Construct via {@link #of(String)} and chain {@link #expectedDevices(String...)}.
 * Instances are immutable; each chained call returns a new one.
 */
public final class KeyChallengeOptions {

    /** A signing key: {@code ES256} or {@code RS256}, chosen by the device. */
    public static final String PURPOSE_SIGN = "sign";
    /** A decrypt key: {@code ECDH-ES} or {@code RSA-OAEP-256}. Refused by the server before wire 8.1. */
    public static final String PURPOSE_DECRYPT = "decrypt";

    private final String purpose;
    private final List<String> expectedDevices;

    private KeyChallengeOptions(String purpose, List<String> expectedDevices) {
        if (!PURPOSE_SIGN.equals(purpose) && !PURPOSE_DECRYPT.equals(purpose)) {
            throw new IllegalArgumentException("purpose must be sign or decrypt (got " + purpose + ")");
        }
        this.purpose = purpose;
        this.expectedDevices = Aliases.copyOrNull(expectedDevices, "expectedDevices");
    }

    /** A key challenge for {@link #PURPOSE_SIGN} or {@link #PURPOSE_DECRYPT}. */
    public static KeyChallengeOptions of(String purpose) {
        return new KeyChallengeOptions(purpose, null);
    }

    /**
     * Aliases ({@code verdict.device.ueid}) you enrolled. The certify leg is
     * refused unless one of them certified the key; an unknown alias is
     * {@code 422 expected_unknown}. Pass the alias of the device that just
     * passed an attest challenge, so the key provably comes from it.
     */
    public KeyChallengeOptions expectedDevices(String... expectedDevices) {
        return expectedDevices(expectedDevices == null ? null : List.of(expectedDevices));
    }

    /** As {@link #expectedDevices(String...)}. */
    public KeyChallengeOptions expectedDevices(List<String> expectedDevices) {
        return new KeyChallengeOptions(purpose, expectedDevices);
    }

    public String purpose() {
        return purpose;
    }

    /** The expected aliases, or {@code null} when the challenge names none. */
    public List<String> expectedDevices() {
        return expectedDevices;
    }
}
