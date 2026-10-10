package io.rootherald.client;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The backend checks device signatures against the JWK it stored from the
 * certification, so the verifier must accept what a TPM emits (raw r||s for
 * P-256, PKCS#1 v1.5 for RSA-2048) and what most libraries emit (DER), and
 * must refuse everything else quietly.
 */
class KeySignaturesTest {

    private static final byte[] MESSAGE = "transfer 100 to acct-42".getBytes(StandardCharsets.UTF_8);

    private record EcFixture(KeyPair pair, Jwk jwk) {
    }

    private record RsaFixture(KeyPair pair, Jwk jwk, int modulusBytes) {
    }

    private static EcFixture p256() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = gen.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        return new EcFixture(pair, Jwk.ec(
                b64url(fixed(pub.getW().getAffineX(), 32)),
                b64url(fixed(pub.getW().getAffineY(), 32))));
    }

    private static RsaFixture rsa(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(bits);
        KeyPair pair = gen.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        return new RsaFixture(pair, Jwk.rsa(b64url(unsigned(pub.getModulus())),
                b64url(unsigned(pub.getPublicExponent()))), bits / 8);
    }

    private static byte[] sign(String algorithm, KeyPair pair, byte[] message) throws Exception {
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(pair.getPrivate());
        signer.update(message);
        return signer.sign();
    }

    private static byte[] signDer(EcFixture f, byte[] message) throws Exception {
        return sign("SHA256withECDSA", f.pair(), message);
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

    private static byte[] unsigned(BigInteger v) {
        byte[] bytes = v.toByteArray();
        return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static String b64url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    @Test
    void acceptsDerSignatureP256() throws Exception {
        EcFixture f = p256();
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, signDer(f, MESSAGE)));
    }

    @Test
    void acceptsRawSignatureP256() throws Exception {
        EcFixture f = p256();
        byte[] raw = derToRaw(signDer(f, MESSAGE), 32);
        assertTrue(raw.length == 64);
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, raw));
    }

    @Test
    void acceptsAnRsa2048Signature() throws Exception {
        RsaFixture f = rsa(2048);
        byte[] sig = sign("SHA256withRSA", f.pair(), MESSAGE);
        assertTrue(sig.length == f.modulusBytes());
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, sig));
    }

    @Test
    void acceptsALongerRsaModulus() throws Exception {
        RsaFixture f = rsa(3072);
        assertTrue(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, sign("SHA256withRSA", f.pair(), MESSAGE)));
    }

    @Test
    void rejectsTamperedMessage() throws Exception {
        EcFixture f = p256();
        byte[] sig = signDer(f, MESSAGE);
        byte[] other = "transfer 999 to acct-42".getBytes(StandardCharsets.UTF_8);
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), other, sig));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), other, derToRaw(sig, 32)));
        RsaFixture r = rsa(2048);
        assertFalse(KeySignatures.verifyKeySignature(r.jwk(), other, sign("SHA256withRSA", r.pair(), MESSAGE)));
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        EcFixture f = p256();
        byte[] raw = derToRaw(signDer(f, MESSAGE), 32);
        raw[10] ^= 0x01;
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, raw));
        RsaFixture r = rsa(2048);
        byte[] sig = sign("SHA256withRSA", r.pair(), MESSAGE);
        sig[10] ^= 0x01;
        assertFalse(KeySignatures.verifyKeySignature(r.jwk(), MESSAGE, sig));
    }

    @Test
    void rejectsSignatureFromAnotherKey() throws Exception {
        EcFixture signer = p256();
        EcFixture other = p256();
        assertFalse(KeySignatures.verifyKeySignature(other.jwk(), MESSAGE, signDer(signer, MESSAGE)));
        RsaFixture rsaSigner = rsa(2048);
        RsaFixture rsaOther = rsa(2048);
        assertFalse(KeySignatures.verifyKeySignature(rsaOther.jwk(), MESSAGE,
                sign("SHA256withRSA", rsaSigner.pair(), MESSAGE)));
    }

    @Test
    void malformedSignaturesAreFalseNotThrown() throws Exception {
        EcFixture f = p256();
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[0]));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, null));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[] {0x30, 0x01}));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[64]));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, new byte[96]));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, "not a signature".getBytes(StandardCharsets.UTF_8)));
        RsaFixture r = rsa(2048);
        assertFalse(KeySignatures.verifyKeySignature(r.jwk(), MESSAGE, null));
        assertFalse(KeySignatures.verifyKeySignature(r.jwk(), MESSAGE, new byte[0]));
        assertFalse(KeySignatures.verifyKeySignature(r.jwk(), MESSAGE, new byte[256]));
    }

    @Test
    void anRsaSignatureOfTheWrongLengthIsFalse() throws Exception {
        RsaFixture f = rsa(2048);
        byte[] sig = sign("SHA256withRSA", f.pair(), MESSAGE);
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, Arrays.copyOf(sig, 255)));
        assertFalse(KeySignatures.verifyKeySignature(f.jwk(), MESSAGE, Arrays.copyOf(sig, 257)));
    }

    @Test
    void unusableJwkIsACallerError() throws Exception {
        EcFixture f = p256();
        byte[] sig = signDer(f, MESSAGE);
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("oct", "P-256", f.jwk().x(), f.jwk().y()), MESSAGE, sig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-384", f.jwk().x(), f.jwk().y()), MESSAGE, sig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-256", "", f.jwk().y()), MESSAGE, sig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-256", "!!not-base64url!!", f.jwk().y()), MESSAGE, sig));
        // A well-formed pair of coordinates that is not a point on the curve.
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                new Jwk("EC", "P-256", f.jwk().x(), f.jwk().x()), MESSAGE, sig));
        // RSA: a short modulus, or no modulus.
        RsaFixture small = rsa(1024);
        byte[] rsaSig = sign("SHA256withRSA", small.pair(), MESSAGE);
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                small.jwk(), MESSAGE, rsaSig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                Jwk.rsa("", "AQAB"), MESSAGE, rsaSig));
        assertThrows(IllegalArgumentException.class, () -> KeySignatures.verifyKeySignature(
                Jwk.rsa("!!", "AQAB"), MESSAGE, rsaSig));
    }

    @Test
    void rawToDerRoundTripsThroughTheJca() throws Exception {
        EcFixture f = p256();
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
