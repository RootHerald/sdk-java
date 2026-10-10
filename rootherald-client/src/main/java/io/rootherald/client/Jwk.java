package io.rootherald.client;

/**
 * The public half of a {@link CertifiedKey} as a JWK (RFC 7518): EC P-256
 * ({@code kty = "EC"}, {@code crv}, {@code x}, {@code y}) or RSA-2048
 * ({@code kty = "RSA"}, {@code n}, {@code e}). The device chooses the family;
 * the server reads it from the key's public area.
 *
 * @param kty key type, {@code "EC"} or {@code "RSA"}
 * @param crv curve, {@code "P-256"}; {@code null} for RSA
 * @param x   base64url, unpadded, big-endian X coordinate; {@code null} for RSA
 * @param y   base64url, unpadded, big-endian Y coordinate; {@code null} for RSA
 * @param n   base64url, unpadded, big-endian modulus; {@code null} for EC
 * @param e   base64url, unpadded, big-endian public exponent; {@code null} for EC
 */
public record Jwk(String kty, String crv, String x, String y, String n, String e) {

    public static final String KTY_EC = "EC";
    public static final String KTY_RSA = "RSA";
    public static final String CRV_P256 = "P-256";

    /** An EC key. */
    public Jwk(String kty, String crv, String x, String y) {
        this(kty, crv, x, y, null, null);
    }

    /** A P-256 key from its coordinates. */
    public static Jwk ec(String x, String y) {
        return new Jwk(KTY_EC, CRV_P256, x, y, null, null);
    }

    /** An RSA key from its modulus and exponent. */
    public static Jwk rsa(String n, String e) {
        return new Jwk(KTY_RSA, null, null, null, n, e);
    }

    public boolean isEc() {
        return KTY_EC.equals(kty);
    }

    public boolean isRsa() {
        return KTY_RSA.equals(kty);
    }
}
