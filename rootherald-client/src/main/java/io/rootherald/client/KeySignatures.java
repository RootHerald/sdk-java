package io.rootherald.client;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Base64;
import java.util.Objects;

/**
 * Verifies signatures made by a {@link CertifiedKey} on the device, using
 * only {@code java.security}.
 * <p>
 * The device signs with the TPM-resident key; the backend checks the
 * signature against the JWK it stored from the attestation. ECDSA over
 * SHA-256 for P-256 and SHA-384 for P-384. The signature may be either the
 * raw {@code r||s} concatenation the TPM emits (64 bytes for P-256, 96 for
 * P-384) or ASN.1 DER.
 */
public final class KeySignatures {

    private KeySignatures() {
    }

    /**
     * @param jwk       the certified key's public half
     * @param message   the bytes that were signed (hashed here; do not pre-hash)
     * @param signature raw {@code r||s} or DER-encoded ECDSA signature
     * @return {@code true} only when the signature verifies; {@code false} for
     *         any malformed or non-matching signature — never throws for one
     * @throws IllegalArgumentException when the JWK itself is not a P-256 /
     *                                  P-384 EC key with decodable coordinates
     */
    public static boolean verifyKeySignature(Jwk jwk, byte[] message, byte[] signature) {
        Objects.requireNonNull(jwk, "jwk");
        Objects.requireNonNull(message, "message");
        if (signature == null || signature.length == 0) {
            return false;
        }

        Curve curve = Curve.of(jwk);
        PublicKey publicKey;
        try {
            publicKey = toPublicKey(jwk, curve);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("jwk is not a usable EC public key: " + ex.getMessage(), ex);
        }

        int rawLength = 2 * curve.coordinateBytes;
        if (signature.length == rawLength) {
            if (verifyDer(publicKey, curve, message, rawToDer(signature))) {
                return true;
            }
            // A DER signature is very unlikely to be exactly this long, but it
            // is possible; fall through and try it as DER before giving up.
            return signature[0] == 0x30 && verifyDer(publicKey, curve, message, signature);
        }
        return verifyDer(publicKey, curve, message, signature);
    }

    private static boolean verifyDer(PublicKey publicKey, Curve curve, byte[] message, byte[] der) {
        try {
            Signature verifier = Signature.getInstance(curve.jcaAlgorithm);
            verifier.initVerify(publicKey);
            verifier.update(message);
            return verifier.verify(der);
        } catch (GeneralSecurityException | RuntimeException ex) {
            // Malformed DER, wrong length, r/s out of range: all "not verified".
            return false;
        }
    }

    private static PublicKey toPublicKey(Jwk jwk, Curve curve) throws GeneralSecurityException {
        BigInteger x = new BigInteger(1, base64Url(jwk.x(), "x"));
        BigInteger y = new BigInteger(1, base64Url(jwk.y(), "y"));
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curve.jcaName));
        ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
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
            // Two P-384 integers fit in one length byte; a long form is only
            // reachable with a longer curve than this class accepts.
            out.write(0x81);
            out.write(length);
        }
    }

    private enum Curve {
        P256("P-256", "secp256r1", "SHA256withECDSA", 32),
        P384("P-384", "secp384r1", "SHA384withECDSA", 48);

        final String jwkName;
        final String jcaName;
        final String jcaAlgorithm;
        final int coordinateBytes;

        Curve(String jwkName, String jcaName, String jcaAlgorithm, int coordinateBytes) {
            this.jwkName = jwkName;
            this.jcaName = jcaName;
            this.jcaAlgorithm = jcaAlgorithm;
            this.coordinateBytes = coordinateBytes;
        }

        static Curve of(Jwk jwk) {
            if (!"EC".equals(jwk.kty())) {
                throw new IllegalArgumentException("jwk.kty must be EC (got " + jwk.kty() + ")");
            }
            for (Curve c : values()) {
                if (c.jwkName.equals(jwk.crv())) {
                    return c;
                }
            }
            throw new IllegalArgumentException("jwk.crv must be P-256 or P-384 (got " + jwk.crv() + ")");
        }
    }
}
