package io.rootherald.client;

/**
 * A relay-friendly nonce minted by
 * {@link BackgroundCheckClient#issueChallenge()}.
 * <p>
 * Relay {@link #nonce()} to the dumb client; it quotes over it and returns an
 * opaque evidence blob, which the server submits to
 * {@link BackgroundCheckClient#verify(String, AttestOptions)} using
 * {@link #challengeId()}.
 *
 * @param challengeId single-use challenge id
 * @param nonce       nonce to relay to the client
 * @param expiresAt   ISO-8601 expiry instant
 */
public record Challenge(String challengeId, String nonce, String expiresAt) {
}
