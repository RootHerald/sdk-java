package io.rootherald.client;

/**
 * A challenge minted by {@link RootHeraldClient#issueChallenge(ChallengeOptions)}.
 * <p>
 * Relay {@link #challenge()} to the client verbatim; it carries the nonce and
 * the ask the server bound to this challenge. The client quotes over it and
 * returns an opaque evidence blob, which the server submits to
 * {@link RootHeraldClient#verify(String, AttestOptions)} using
 * {@link #nonce()}.
 *
 * @param nonce     the backend's handle for this challenge: 32 random bytes,
 *                  base64url without padding, the same bytes as the second
 *                  segment of {@link #challenge()}
 * @param challenge the opaque {@code rhc1.<nonce>.<ask>} string to relay to
 *                  the client verbatim
 * @param expiresAt ISO-8601 expiry instant
 */
public record Challenge(String nonce, String challenge, String expiresAt) {
}
