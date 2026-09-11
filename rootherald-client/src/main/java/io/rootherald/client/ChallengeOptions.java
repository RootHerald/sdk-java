package io.rootherald.client;

import java.util.List;

/**
 * Options for {@link RootHeraldClient#issueChallenge(ChallengeOptions)}.
 * <p>
 * The challenge carries the ask: what the device has to prove is fixed when
 * the challenge is minted, not at verify time. Construct via
 * {@link #defaults()} and chain {@link #ask(String...)},
 * {@link #keyPurpose(String)} and {@link #deviceHint(String)} as needed.
 * Instances are immutable; each chained call returns a new one.
 * <p>
 * There is no policy option. Policies bind to the API key, and the server
 * pins the resolved policy on the challenge when it is minted; a
 * {@code policy} field in a hand-built request body is refused with
 * 400 {@code policy_bound_to_key}.
 */
public final class ChallengeOptions {

    /** Ask: prove which enrolled device this is. */
    public static final String ASK_IDENTITY = "identity";
    /** Ask: prove the boot / configuration state (quote + event log). */
    public static final String ASK_POSTURE = "posture";
    /** Ask: certify a fresh TPM-resident signing key under the AK. */
    public static final String ASK_KEY = "key";

    /** The only key purpose today. */
    public static final String KEY_PURPOSE_SIGN = "sign";

    private final List<String> ask;
    private final String keyPurpose;
    private final String deviceHint;

    private ChallengeOptions(List<String> ask, String keyPurpose, String deviceHint) {
        this.ask = ask == null ? null : List.copyOf(ask);
        this.keyPurpose = keyPurpose;
        this.deviceHint = deviceHint;
    }

    /** No ask, key purpose or hint: the server's default of identity + posture. */
    public static ChallengeOptions defaults() {
        return new ChallengeOptions(null, null, null);
    }

    /**
     * What the device must prove: any of {@link #ASK_IDENTITY},
     * {@link #ASK_POSTURE}, {@link #ASK_KEY}. Omitted (or empty) means the
     * server default, identity + posture.
     */
    public ChallengeOptions ask(String... ask) {
        return ask(ask == null ? null : List.of(ask));
    }

    /** As {@link #ask(String...)}. */
    public ChallengeOptions ask(List<String> ask) {
        return new ChallengeOptions(ask, keyPurpose, deviceHint);
    }

    /** Purpose of the certified key when asking for {@link #ASK_KEY}; {@link #KEY_PURPOSE_SIGN}. */
    public ChallengeOptions keyPurpose(String keyPurpose) {
        return new ChallengeOptions(ask, keyPurpose, deviceHint);
    }

    /** Optional advisory device hint. */
    public ChallengeOptions deviceHint(String deviceHint) {
        return new ChallengeOptions(ask, keyPurpose, deviceHint);
    }

    /** The ask list, or {@code null} when left to the server default. */
    public List<String> ask() {
        return ask;
    }

    public String keyPurpose() {
        return keyPurpose;
    }

    public String deviceHint() {
        return deviceHint;
    }
}
