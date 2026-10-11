package io.rootherald.client;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Verifies signatures made by a {@link CertifiedKey} on the device, using
 * only {@code java.security}.
 * <p>
 * The device signs with the key it minted; the backend checks the signature
 * against the JWK it stored from {@link RootHeraldClient#certifyKey(String, String)}.
 * An EC P-256 key checks ES256 (ECDSA over SHA-256), with the signature either
 * the raw {@code r||s} the TPM emits (64 bytes) or ASN.1 DER. An RSA key
 * checks RS256 (PKCS#1 v1.5 over SHA-256) with a modulus of at least 2048
 * bits and a signature exactly the modulus length (256 bytes for RSA-2048).
 * <p>
 * A signature proves possession of the key at that moment, not how the
 * machine booted; run an attest challenge for that.
 */
public final class KeySignatures {

    private static final int MIN_RSA_MODULUS_BITS = 2048;
    private static final int P256_COORDINATE_BYTES = 32;

    private KeySignatures() {
    }

    /**
     * @param jwk       the certified key's public half
     * @param message   the bytes that were signed (hashed here; do not pre-hash)
     * @param signature raw {@code r||s} or DER-encoded ECDSA signature, or a PKCS#1 v1.5 RSA signature
     * @return {@code true} only when the signature verifies; {@code false} for
     *         any malformed or non-matching signature — never throws for one
     * @throws IllegalArgumentException when the JWK itself is not a P-256 EC key
     *                                  or an RSA key of at least 2048 bits with
     *                                  decodable parameters
     */
    public static boolean verifyKeySignature(Jwk jwk, byte[] message, byte[] signature) {
        Objects.requireNonNull(jwk, "jwk");
        Objects.requireNonNull(message, "message");
        if (jwk.isRsa()) {
            return verifyRs256(jwk, message, signature);
        }
        if (jwk.isEc()) {
            return verifyEs256(jwk, message, signature);
        }
        throw new IllegalArgumentException("jwk.kty must be EC or RSA (got " + jwk.kty() + ")");
    }

    private static boolean verifyEs256(Jwk jwk, byte[] message, byte[] signature) {
        if (!Jwk.CRV_P256.equals(jwk.crv())) {
            throw new IllegalArgumentException("jwk.crv must be P-256 (got " + jwk.crv() + ")");
        }
        PublicKey publicKey;
        try {
            publicKey = toEcPublicKey(jwk);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("jwk is not a usable EC public key: " + ex.getMessage(), ex);
        }
        if (signature == null || signature.length == 0) {
            return false;
        }

        if (signature.length == 2 * P256_COORDINATE_BYTES) {
            if (verify("SHA256withECDSA", publicKey, message, rawToDer(signature))) {
                return true;
            }
            // A DER signature is very unlikely to be exactly this long, but it
            // is possible; fall through and try it as DER before giving up.
            return signature[0] == 0x30 && verify("SHA256withECDSA", publicKey, message, signature);
        }
        return verify("SHA256withECDSA", publicKey, message, signature);
    }

    private static boolean verifyRs256(Jwk jwk, byte[] message, byte[] signature) {
        BigInteger n = new BigInteger(1, base64Url(jwk.n(), "n"));
        BigInteger e = new BigInteger(1, base64Url(jwk.e(), "e"));
        if (n.bitLength() < MIN_RSA_MODULUS_BITS) {
            throw new IllegalArgumentException("jwk.n must be at least " + MIN_RSA_MODULUS_BITS
                    + " bits (got " + n.bitLength() + ")");
        }
        PublicKey publicKey;
        try {
            publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("jwk is not a usable RSA public key: " + ex.getMessage(), ex);
        }
        if (signature == null || signature.length != (n.bitLength() + 7) / 8) {
            return false;
        }
        return verify("SHA256withRSA", publicKey, message, signature);
    }

    private static boolean verify(String algorithm, PublicKey publicKey, byte[] message, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(algorithm);
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException ex) {
            // Malformed DER, wrong length, r/s out of range: all "not verified".
            return false;
        }
    }

    private static PublicKey toEcPublicKey(Jwk jwk) throws GeneralSecurityException {
        return ecPublicKey(new BigInteger(1, base64Url(jwk.x(), "x")), new BigInteger(1, base64Url(jwk.y(), "y")));
    }

    /** A P-256 public key from its affine coordinates, refused when the point is off the curve. */
    static PublicKey ecPublicKey(BigInteger x, BigInteger y) throws GeneralSecurityException {
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        requireOnCurve(x, y, spec.getCurve());
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
    }

    /**
     * y^2 = x^3 + ax + b over the prime field. The JCA does not always check
     * this when building the key, and a point off the curve is a bad JWK, not
     * a bad signature.
     */
    private static void requireOnCurve(BigInteger x, BigInteger y, EllipticCurve curve) {
        BigInteger p = ((ECFieldFp) curve.getField()).getP();
        if (x.signum() < 0 || x.compareTo(p) >= 0 || y.signum() < 0 || y.compareTo(p) >= 0) {
            throw new IllegalArgumentException("jwk point is not on " + curve);
        }
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.pow(3).add(curve.getA().multiply(x)).add(curve.getB()).mod(p);
        if (!lhs.equals(rhs)) {
            throw new IllegalArgumentException("jwk point is not on the curve");
        }
    }

    private static byte[] base64Url(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("jwk." + field + " is required");
        }
        try {
            return Base64.getUrlDecoder().decode(value);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("jwk." + field + " is not base64url", ex);
        }
    }

    /** Encode raw {@code r||s} as the DER {@code SEQUENCE { INTEGER r, INTEGER s }} the JCA expects. */
    static byte[] rawToDer(byte[] raw) {
        int half = raw.length / 2;
        byte[] r = derInteger(raw, 0, half);
        byte[] s = derInteger(raw, half, half);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x30);
        writeLength(out, r.length + s.length);
        out.write(r, 0, r.length);
        out.write(s, 0, s.length);
        return out.toByteArray();
    }

    private static byte[] derInteger(byte[] src, int offset, int length) {
        int start = offset;
        int end = offset + length;
        while (start < end - 1 && src[start] == 0) {
            start++;
        }
        boolean pad = (src[start] & 0x80) != 0;
        int bodyLength = (end - start) + (pad ? 1 : 0);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0x02);
        writeLength(out, bodyLength);
        if (pad) {
            out.write(0);
        }
        out.write(src, start, end - start);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
        } else {
            // Two P-256 integers with padding are at most 70 bytes; the long
            // form is only reachable with a longer curve than this class accepts.
            out.write(0x81);
            out.write(length);
        }
    }
}
