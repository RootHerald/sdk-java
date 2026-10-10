package io.rootherald.client;

import java.time.Instant;

/**
 * The key RootHerald registered from {@link RootHeraldClient#certifyKey(String, String)}:
 * created inside the device and certified by the installation's attestation
 * key. Store it against the device's alias; verify later signatures from the
 * device with {@link KeySignatures#verifyKeySignature(Jwk, byte[], byte[])}.
 * The private half never leaves the device, and RootHerald never holds it.
 * <p>
 * {@code keyId} identifies an installation's credential, never a device:
 * bind accounts to {@code deviceId}. Minting again for the same purpose
 * rotates the key under the same {@code keyId}; a re-enrolled installation
 * gets new key IDs.
 *
 * @param deviceId      this tenant's alias for the device that holds the key
 *                      ({@code verdict.device.ueid})
 * @param keyId         RootHerald's id for this key; stable across rotations of the same purpose
 * @param purpose       {@link KeyChallengeOptions#PURPOSE_SIGN} or {@link KeyChallengeOptions#PURPOSE_DECRYPT}
 * @param alg           {@code ES256} / {@code RS256} for a sign key; {@code ECDH-ES} /
 *                      {@code RSA-OAEP-256} for a decrypt key
 * @param format        {@code jwe} or {@code apple-ecies} for a decrypt key; {@code null} for a sign key
 * @param jwk           the public half
 * @param hardwareBound {@code true} when the key lives in a TPM and was certified by the
 *                      installation's AK; {@code false} on macOS, where possession alone is proved
 * @param certifiedAt   when the certification happened
 */
public record CertifiedKey(String deviceId, String keyId, String purpose, String alg, String format,
                           Jwk jwk, boolean hardwareBound, Instant certifiedAt) {
}
