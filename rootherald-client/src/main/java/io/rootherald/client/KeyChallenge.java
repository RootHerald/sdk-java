package io.rootherald.client;

/**
 * A key challenge minted by {@link RootHeraldClient#issueKeyChallenge(KeyChallengeOptions)}.
 * <p>
 * Relay {@link #keyChallenge()} to the client verbatim; its {@code MintKey}
 * creates the key and answers with a certification, which the backend
 * submits to {@link RootHeraldClient#certifyKey(String, String)} under
 * {@link #nonce()}.
 *
 * @param nonce        the backend's handle for this key challenge: 32 random
 *                     bytes, base64url without padding, the same bytes as the
 *                     second segment of {@link #keyChallenge()}
 * @param keyChallenge the opaque {@code rhk1c.<nonce>.<purpose>} string to
 *                     relay to the client verbatim
 * @param expiresAt    ISO-8601 expiry instant
 */
public record KeyChallenge(String nonce, String keyChallenge, String expiresAt) {
}
