package io.rootherald.client;

/**
 * Options for {@link RootHeraldClient#verify(String, AttestOptions)}.
 * <p>
 * Construct via {@link #of(String)} for the common case (challenge id only) and
 * chain {@link #requestedDisclosureClass(String)} as needed.
 * <p>
 * There is no policy option. The appraisal runs under the policy bound to the
 * API key, pinned on the challenge when it was minted; a {@code policy} field
 * in a hand-built request body is refused with 400 {@code policy_bound_to_key}.
 */
public final class AttestOptions {

    private final String challengeId;
    private final String requestedDisclosureClass;

    private AttestOptions(String challengeId, String requestedDisclosureClass) {
        if (challengeId == null || challengeId.isEmpty()) {
            throw new IllegalArgumentException("challengeId is required (from issueChallenge)");
        }
        this.challengeId = challengeId;
        this.requestedDisclosureClass = requestedDisclosureClass;
    }

    /** The single-use challenge id from {@link RootHeraldClient#issueChallenge()}. */
    public static AttestOptions of(String challengeId) {
        return new AttestOptions(challengeId, null);
    }

    /**
     * Requested disclosure class for the returned verdict — one of
     * {@code "verdict"}, {@code "pseudonymous"}, {@code "derived"}, or
     * {@code "full"}. Optional; omitted from the request when not set, letting
     * the resolved policy decide.
     */
    public AttestOptions requestedDisclosureClass(String requestedDisclosureClass) {
        return new AttestOptions(challengeId, requestedDisclosureClass);
    }

    public String challengeId() {
        return challengeId;
    }

    public String requestedDisclosureClass() {
        return requestedDisclosureClass;
    }
}
