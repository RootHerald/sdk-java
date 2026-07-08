package io.rootherald.client;

/**
 * Options for {@link BackgroundCheckClient#verify(String, AttestOptions)}.
 * <p>
 * Construct via {@link #of(String)} for the common case (challenge id only) and
 * chain {@link #policy(String)} as needed.
 */
public final class AttestOptions {

    private final String challengeId;
    private final String policy;

    private AttestOptions(String challengeId, String policy) {
        if (challengeId == null || challengeId.isEmpty()) {
            throw new IllegalArgumentException("challengeId is required (from issueChallenge)");
        }
        this.challengeId = challengeId;
        this.policy = policy;
    }

    /** The single-use challenge id from {@link BackgroundCheckClient#issueChallenge()}. */
    public static AttestOptions of(String challengeId) {
        return new AttestOptions(challengeId, null);
    }

    /**
     * Caller-named policy: a tenant-owned policy id/name or a
     * {@code rootherald:builtin:*} name. Unknown/foreign names fail closed (422).
     */
    public AttestOptions policy(String policy) {
        return new AttestOptions(challengeId, policy);
    }

    public String challengeId() {
        return challengeId;
    }

    public String policy() {
        return policy;
    }
}
