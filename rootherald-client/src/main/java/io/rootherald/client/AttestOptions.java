package io.rootherald.client;

import java.util.List;

/**
 * Options for {@link RootHeraldClient#verify(String, AttestOptions)}.
 * <p>
 * Construct via {@link #of(String)} for the common case (nonce only) and
 * chain {@link #requestedDisclosureClass(String)}, {@link #expectedKey(String)}
 * and {@link #expectedDevices(String...)} as needed.
 * <p>
 * There is no policy option. The appraisal runs under the policy bound to the
 * API key, pinned on the challenge when it was minted; a {@code policy} field
 * in a hand-built request body is refused with 400 {@code policy_bound_to_key}.
 */
public final class AttestOptions {

    private final String nonce;
    private final String requestedDisclosureClass;
    private final String expectedKey;
    private final List<String> expectedDevices;

    private AttestOptions(String nonce, String requestedDisclosureClass,
                          String expectedKey, List<String> expectedDevices) {
        if (nonce == null || nonce.isEmpty()) {
            throw new IllegalArgumentException("nonce is required (from issueChallenge)");
        }
        this.nonce = nonce;
        this.requestedDisclosureClass = requestedDisclosureClass;
        this.expectedKey = Aliases.textOrNull(expectedKey, "expectedKey");
        this.expectedDevices = Aliases.copyOrNull(expectedDevices, "expectedDevices");
    }

    /** The challenge handle, {@link Challenge#nonce()}, from {@link RootHeraldClient#issueChallenge()}. */
    public static AttestOptions of(String nonce) {
        return new AttestOptions(nonce, null, null, null);
    }

    /**
     * Requested disclosure class for the returned verdict — one of
     * {@code "verdict"}, {@code "pseudonymous"}, {@code "derived"}, or
     * {@code "full"}. Optional; omitted from the request when not set, letting
     * the resolved policy decide.
     */
    public AttestOptions requestedDisclosureClass(String requestedDisclosureClass) {
        return new AttestOptions(nonce, requestedDisclosureClass, expectedKey, expectedDevices);
    }

    /**
     * The {@code expectedKey} the challenge was issued with. {@code verify}
     * refuses a verdict that does not echo it
     * ({@link io.rootherald.ExpectedNotEnforcedException}), so a server that
     * ignored the binding cannot pass silently.
     */
    public AttestOptions expectedKey(String expectedKey) {
        return new AttestOptions(nonce, requestedDisclosureClass, expectedKey, expectedDevices);
    }

    /**
     * The {@code expectedDevices} the challenge was issued with. {@code verify}
     * refuses a verdict that does not echo them, and a passing verdict naming
     * a device outside them ({@link io.rootherald.ExpectedNotEnforcedException}).
     */
    public AttestOptions expectedDevices(String... expectedDevices) {
        return expectedDevices(expectedDevices == null ? null : List.of(expectedDevices));
    }

    /** As {@link #expectedDevices(String...)}. */
    public AttestOptions expectedDevices(List<String> expectedDevices) {
        return new AttestOptions(nonce, requestedDisclosureClass, expectedKey, expectedDevices);
    }

    public String nonce() {
        return nonce;
    }

    public String requestedDisclosureClass() {
        return requestedDisclosureClass;
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
