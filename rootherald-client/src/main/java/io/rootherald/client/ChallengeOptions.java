package io.rootherald.client;

import java.util.List;

/**
 * Options for {@link RootHeraldClient#issueChallenge(ChallengeOptions)}.
 * <p>
 * The challenge carries the ask: what the device has to prove is fixed when
 * the challenge is minted, not at verify time. Construct via
 * {@link #defaults()} and chain {@link #ask(String...)},
 * {@link #expectedKey(String)} and {@link #expectedDevices(String...)} as
 * needed. Instances are immutable; each chained call returns a new one.
 * <p>
 * Keys are never asked for here; they have their own ceremony
 * ({@link RootHeraldClient#issueKeyChallenge(KeyChallengeOptions)}). A
 * challenge that still asks for {@code "key"} is refused with 400
 * {@code invalid_ask}.
 * <p>
 * There is no policy option. Policies bind to the API key, and the server
 * pins the resolved policy on the challenge when it is minted; a
 * {@code policy} field in a hand-built request body is refused with
 * 400 {@code policy_bound_to_key}.
 */
public final class ChallengeOptions {

    /** Ask: prove which enrolled installation this is (quote under its AK). */
    public static final String ASK_IDENTITY = "identity";
    /** Ask: prove the boot / configuration state (quote + event log). */
    public static final String ASK_POSTURE = "posture";

    private final List<String> ask;
    private final String expectedKey;
    private final List<String> expectedDevices;

    private ChallengeOptions(List<String> ask, String expectedKey, List<String> expectedDevices) {
        this.ask = ask == null ? null : List.copyOf(ask);
        this.expectedKey = Aliases.textOrNull(expectedKey, "expectedKey");
        this.expectedDevices = Aliases.copyOrNull(expectedDevices, "expectedDevices");
    }

    /** No ask and no binding: the server's default of identity + posture, from any device. */
    public static ChallengeOptions defaults() {
        return new ChallengeOptions(null, null, null);
    }

    /**
     * What the device must prove: {@link #ASK_IDENTITY} and/or
     * {@link #ASK_POSTURE}. Omitted (or empty) means the server default,
     * identity + posture.
     */
    public ChallengeOptions ask(String... ask) {
        return ask(ask == null ? null : List.of(ask));
    }

    /** As {@link #ask(String...)}. */
    public ChallengeOptions ask(List<String> ask) {
        return new ChallengeOptions(ask, expectedKey, expectedDevices);
    }

    /**
     * The {@code keyId} of a key you certified. Only the installation holding
     * that key can pass; any other answers a failing verdict with reason
     * {@code expected_device_mismatch}. An unknown id is
     * {@code 422 expected_unknown}. Pass the same value to
     * {@link AttestOptions#expectedKey(String)}.
     */
    public ChallengeOptions expectedKey(String expectedKey) {
        return new ChallengeOptions(ask, expectedKey, expectedDevices);
    }

    /**
     * Aliases ({@code verdict.device.ueid}) you enrolled. Only one of them can
     * pass; any other device answers a failing verdict with reason
     * {@code expected_device_mismatch}. An unknown alias is
     * {@code 422 expected_unknown}. Pass the same values to
     * {@link AttestOptions#expectedDevices(String...)}.
     */
    public ChallengeOptions expectedDevices(String... expectedDevices) {
        return expectedDevices(expectedDevices == null ? null : List.of(expectedDevices));
    }

    /** As {@link #expectedDevices(String...)}. */
    public ChallengeOptions expectedDevices(List<String> expectedDevices) {
        return new ChallengeOptions(ask, expectedKey, expectedDevices);
    }

    /** The ask list, or {@code null} when left to the server default. */
    public List<String> ask() {
        return ask;
    }

    /** The expected key id, or {@code null}. */
    public String expectedKey() {
        return expectedKey;
    }

    /** The expected aliases, or {@code null}. */
    public List<String> expectedDevices() {
        return expectedDevices;
    }
}
