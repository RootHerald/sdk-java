package io.rootherald.client;

/**
 * An EC public key as a JWK (RFC 7518 §6.2.1): the {@code jwk} of a
 * {@link CertifiedKey}.
 *
 * @param kty key type; always {@code "EC"}
 * @param crv curve: {@code "P-256"} or {@code "P-384"}
 * @param x   base64url, unpadded, big-endian X coordinate
 * @param y   base64url, unpadded, big-endian Y coordinate
 */
public record Jwk(String kty, String crv, String x, String y) {
}
