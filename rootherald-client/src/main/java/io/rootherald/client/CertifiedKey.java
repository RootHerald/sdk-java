package io.rootherald.client;

import java.time.Instant;

/**
 * A TPM-resident signing key the appraisal certified. Returned on
 * {@link AttestResult#key()} when the challenge asked for
 * {@link ChallengeOptions#ASK_KEY} and the verdict passed.
 * <p>
 * Store it against the user; verify later signatures from the device with
 * {@link KeySignatures#verifyKeySignature(Jwk, byte[], byte[])}. The private
 * half never leaves the TPM that made it, and RootHerald never holds it.
 *
 * @param keyId       RootHerald's id for this key; stable for the key's lifetime
 * @param jwk         the public key
 * @param purpose     what the key is certified for; echoes the challenge's key purpose
 * @param authPolicy  base64 {@code authPolicy} digest from the key's public
 *                    area, or {@code null} for a key created without one
 * @param certifiedAt when the certification happened
 */
public record CertifiedKey(String keyId, Jwk jwk, String purpose, String authPolicy, Instant certifiedAt) {
}
