package io.rootherald.client;

/**
 * A challenge minted by {@link RootHeraldClient#issueChallenge(ChallengeOptions)}.
 * <p>
 * Relay {@link #challenge()} to the client verbatim; it carries the nonce and
 * the ask the server bound to this challenge. The client quotes over it and
 * returns an opaque evidence blob, which the server submits to
 * {@link RootHeraldClient#verify(String, AttestOptions)} using
 * {@link #challengeId()}.
 *
 * @param challengeId single-use challenge id
 * @param challenge   the opaque challenge string to relay to the client
 *                    verbatim, or {@code null} when the server did not
 *                    return one
 * @param nonce       the bare nonce the TPM signs over
 * @param expiresAt   ISO-8601 expiry instant
 */
public record Challenge(String challengeId, String challenge, String nonce, String expiresAt) {

    /** A challenge without the relayable {@code challenge} string. */
    public Challenge(String challengeId, String nonce, String expiresAt) {
        this(challengeId, null, nonce, expiresAt);
    }
}
