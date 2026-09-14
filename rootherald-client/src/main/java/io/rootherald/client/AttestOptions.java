package io.rootherald.client;

/**
 * Options for {@link RootHeraldClient#verify(String, AttestOptions)}.
 * <p>
 * Construct via {@link #of(String)} for the common case (nonce only) and
 * chain {@link #requestedDisclosureClass(String)} as needed.
 * <p>
 * There is no policy option. The appraisal runs under the policy bound to the
 * API key, pinned on the challenge when it was minted; a {@code policy} field
 * in a hand-built request body is refused with 400 {@code policy_bound_to_key}.
 */
public final class AttestOptions {

    private final String nonce;
    private final String requestedDisclosureClass;

    private AttestOptions(String nonce, String requestedDisclosureClass) {
        if (nonce == null || nonce.isEmpty()) {
            throw new IllegalArgumentException("nonce is required (from issueChallenge)");
        }
        this.nonce = nonce;
        this.requestedDisclosureClass = requestedDisclosureClass;
    }

    /** The challenge handle, {@link Challenge#nonce()}, from {@link RootHeraldClient#issueChallenge()}. */
    public static AttestOptions of(String nonce) {
        return new AttestOptions(nonce, null);
    }

    /**
     * Requested disclosure class for the returned verdict — one of
     * {@code "verdict"}, {@code "pseudonymous"}, {@code "derived"}, or
     * {@code "full"}. Optional; omitted from the request when not set, letting
     * the resolved policy decide.
     */
    public AttestOptions requestedDisclosureClass(String requestedDisclosureClass) {
        return new AttestOptions(nonce, requestedDisclosureClass);
    }

    public String nonce() {
        return nonce;
    }

    public String requestedDisclosureClass() {
        return requestedDisclosureClass;
    }
}
