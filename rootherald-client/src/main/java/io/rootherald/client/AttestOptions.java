package io.rootherald.client;

/**
 * Options for {@link BackgroundCheckClient#verify(String, AttestOptions)}.
 * <p>
 * Construct via {@link #of(String)} for the common case (challenge id only) and
 * chain {@link #policy(String)} / {@link #returnToken(boolean)} as needed.
 */
public final class AttestOptions {

    private final String challengeId;
    private final String policy;
    private final boolean returnToken;

    private AttestOptions(String challengeId, String policy, boolean returnToken) {
        if (challengeId == null || challengeId.isEmpty()) {
            throw new IllegalArgumentException("challengeId is required (from issueChallenge)");
        }
        this.challengeId = challengeId;
        this.policy = policy;
        this.returnToken = returnToken;
    }

    /** The single-use challenge id from {@link BackgroundCheckClient#issueChallenge()}. */
    public static AttestOptions of(String challengeId) {
        return new AttestOptions(challengeId, null, false);
    }

    /**
     * Caller-named policy: a tenant-owned policy id/name or a
     * {@code rootherald:builtin:*} name. Unknown/foreign names fail closed (422).
     */
    public AttestOptions policy(String policy) {
        return new AttestOptions(challengeId, policy, returnToken);
    }

    /** Opt-in signed EAT (JWT) output. Default false. */
    public AttestOptions returnToken(boolean returnToken) {
        return new AttestOptions(challengeId, policy, returnToken);
    }

    public String challengeId() {
        return challengeId;
    }

    public String policy() {
        return policy;
    }

    public boolean returnTokenRequested() {
        return returnToken;
    }
}
