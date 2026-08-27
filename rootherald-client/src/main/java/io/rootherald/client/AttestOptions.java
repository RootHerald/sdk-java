package io.rootherald.client;

/**
 * Options for {@link RootHeraldClient#verify(String, AttestOptions)}.
 * <p>
 * Construct via {@link #of(String)} for the common case (challenge id only) and
 * chain {@link #policy(String)} as needed.
 */
public final class AttestOptions {

    private final String challengeId;
    private final String policy;
    private final String requestedDisclosureClass;

    private AttestOptions(String challengeId, String policy, String requestedDisclosureClass) {
        if (challengeId == null || challengeId.isEmpty()) {
            throw new IllegalArgumentException("challengeId is required (from issueChallenge)");
        }
        this.challengeId = challengeId;
        this.policy = policy;
        this.requestedDisclosureClass = requestedDisclosureClass;
    }

    /** The single-use challenge id from {@link RootHeraldClient#issueChallenge()}. */
    public static AttestOptions of(String challengeId) {
        return new AttestOptions(challengeId, null, null);
    }

    /**
     * Caller-named policy: a tenant-owned policy id/name or a
     * {@code rootherald:builtin:*} name. Unknown/foreign names fail closed (422).
     */
    public AttestOptions policy(String policy) {
        return new AttestOptions(challengeId, policy, requestedDisclosureClass);
    }

    /**
     * Requested disclosure class for the returned verdict — one of
     * {@code "verdict"}, {@code "pseudonymous"}, {@code "derived"}, or
     * {@code "full"}. Optional; omitted from the request when not set, letting
     * the resolved policy decide.
     */
    public AttestOptions requestedDisclosureClass(String requestedDisclosureClass) {
        return new AttestOptions(challengeId, policy, requestedDisclosureClass);
    }

    public String challengeId() {
        return challengeId;
    }

    public String policy() {
        return policy;
    }

    public String requestedDisclosureClass() {
        return requestedDisclosureClass;
    }
}
