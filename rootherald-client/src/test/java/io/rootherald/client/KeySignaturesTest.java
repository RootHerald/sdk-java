package io.rootherald.client;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The backend checks device signatures against the JWK it stored from the
 * attestation, so the verifier must accept what a TPM emits (raw r||s) and
 * what most libraries emit (DER), and must refuse everything else quietly.
 */
class KeySignaturesTest {

    private static final byte[] MESSAGE = "transfer 100 to acct-42".getBytes(StandardCharsets.UTF_8);

    private record Fixture(KeyPair pair, Jwk jwk, String algorithm, int coordinateBytes) {
    }

    private static Fixture fixture(String curve) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec(curve.equals("P-256") ? "secp256r1" : "secp384r1"));
        KeyPair pair = gen.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        int size = curve.equals("P-256") ? 32 : 48;
        Jwk jwk = new Jwk("EC", curve,
                b64url(fixed(pub.getW().getAffineX(), size)),
                b64url(fixed(pub.getW().getAffineY(), size)));
        return new Fixture(pair, jwk, curve.equals("P-256") ? "SHA256withECDSA" : "SHA384withECDSA", size);
    }

    private static byte[] signDer(Fixture f, byte[] message) throws Exception {
        Signature signer = Signature.getInstance(f.algorithm());
        signer.initSign(f.pair().getPrivate());
        signer.update(message);
        return signer.sign();
    }

    /** DER SEQUENCE { INTEGER r, INTEGER s } to fixed-width r||s. */
    private static byte[] derToRaw(byte[] der, int size) {
        int i = 2; // 0x30 len
        if ((der[1] & 0x80) != 0) {
            i = 2 + (der[1] & 0x7F);
        }
        int rLen = der[i + 1];
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(der, i + 2, i + 2 + rLen));
        int j = i + 2 + rLen;
        int sLen = der[j + 1];
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(der, j + 2, j + 2 + sLen));
        byte[] raw = new byte[2 * size];
        System.arraycopy(fixed(r, size), 0, raw, 0, size);
        System.arraycopy(fixed(s, size), 0, raw, size, size);
        return raw;
    }

    private static byte[] fixed(BigInteger v, int size) {
        byte[] bytes = v.toByteArray();
        byte[] out = new byte[size];
        int start = Math.max(0, bytes.length - size);
        System.arraycopy(bytes, start, out, size - (bytes.length - start), bytes.length - start);
        return out;
    }

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Test
    void acceptsDerSignatureP256() throws Exception {
        Fixture f = fixture("P-256");
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, signDer(f, MESSAGE)));
    }

    @Test
    void acceptsRawSignatureP256() throws Exception {
        Fixture f = fixture("P-256");
        byte[] raw = derToRaw(signDer(f, MESSAGE), f.coordinateBytes());
        assertTrue(raw.length == 64);
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, raw));
    }

    @Test
    void acceptsDerAndRawP384() throws Exception {
        Fixture f = fixture("P-384");
        byte[] der = signDer(f, MESSAGE);
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, der));
        byte[] raw = derToRaw(der, f.coordinateBytes());
        assertTrue(raw.length == 96);
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, raw));
    }

    @Test
    void rejectsTamperedMessage() throws Exception {
        Fixture f = fixture("P-256");
        byte[] sig = signDer(f, MESSAGE);
        byte[] other = "transfer 999 to acct-42".getBytes(StandardCharsets.UTF_8);
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), other, sig));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), other, derToRaw(sig, 32)));
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        Fixture f = fixture("P-256");
        byte[] raw = derToRaw(signDer(f, MESSAGE), 32);
        raw[10] ^= 0x01;
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, raw));
    }

    @Test
    void rejectsSignatureFromAnotherKey() throws Exception {
        Fixture signer = fixture("P-256");
        Fixture other = fixture("P-256");
        assertFalse(KeySignatures.verifyKeySignature(other.jwk(), MESSAGE, signDer(signer, MESSAGE)));
    }

    @Test
    void malformedSignaturesAreFalseNotThrown() throws Exception {
        Fixture f = fixture("P-256");
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[0]));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, null));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[] {0x30, 0x01}));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[64]));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[96]));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, "not a signature".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rawSignatureOfTheWrongCurveWidthIsFalse() throws Exception {
        Fixture p256 = fixture("P-256");
        Fixture p384 = fixture("P-384");
        byte[] raw384 = derToRaw(signDer(p384, MESSAGE), 48);
        assertFalse(KeySignatures.verifyKeySignature(p256.jwk(), MESSAGE, raw384));
    }

    @Test
    void unusableJwkIsACallerError() throws Exception {
        Fixture f = fixture("P-256");
        byte[] sig = signDer(f, MESSAGE);
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("RSA", "P-256", f.jwk().x(), f.jwk().y()), MESSAGE, sig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-521", f.jwk().x(), f.jwk().y()), MESSAGE, sig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-256", "", f.jwk().y()), MESSAGE, sig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-256", "!!not-base64url!!", f.jwk().y()), MESSAGE, sig));
    }

    @Test
    void rawToDerRoundTripsThroughTheJca() throws Exception {
        Fixture f = fixture("P-256");
        byte[] der = signDer(f, MESSAGE);
        byte[] raw = derToRaw(der, 32);
        // Re-encoding raw must yield a DER the JCA verifies (it may differ
        // byte-for-byte from the original only if the original was non-minimal).
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(f.pair().getPublic());
        verifier.update(MESSAGE);
        assertTrue(verifier.verify(KeySignatures.rawToDer(raw)));
    }
}
