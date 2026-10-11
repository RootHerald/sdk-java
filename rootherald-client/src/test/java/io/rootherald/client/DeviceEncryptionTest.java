package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The envelope must be exactly what the device's whitelist parser opens: one
 * header shape, the header as AAD, a fresh ephemeral key per call; and every
 * key that cannot open it is refused before anything is encrypted.
 */
class DeviceEncryptionTest {

    private static final byte[] PLAINTEXT = "{\"session\":\"s-1\",\"exp\":1893456000}".getBytes(StandardCharsets.UTF_8);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private record Fixture(CertifiedKey key, PrivateKey priv) {
    }

    private static CertifiedKey key(String purpose, String alg, String format, Jwk jwk) {
        return new CertifiedKey("dev-alias", "key-1", purpose, alg, format, jwk, true, Instant.EPOCH);
    }

    private static KeyPair p256Pair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static Fixture ec() throws Exception {
        KeyPair pair = p256Pair();
        ECPublicKey pub = (ECPublicKey) pair.getPublic();
        Jwk jwk = Jwk.ec(B64.encodeToString(DeviceEncryption.fixed(pub.getW().getAffineX(), 32)),
                B64.encodeToString(DeviceEncryption.fixed(pub.getW().getAffineY(), 32)));
        return new Fixture(key(KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", "jwe", jwk), pair.getPrivate());
    }

    private static Fixture rsa(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(bits);
        KeyPair pair = gen.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
        Jwk jwk = Jwk.rsa(B64.encodeToString(unsigned(pub.getModulus())), B64.encodeToString(unsigned(pub.getPublicExponent())));
        return new Fixture(key(KeyChallengeOptions.PURPOSE_DECRYPT, "RSA-OAEP-256", "jwe", jwk), pair.getPrivate());
    }

    private static byte[] unsigned(BigInteger v) {
        byte[] raw = v.toByteArray();
        return raw[0] == 0 ? Arrays.copyOfRange(raw, 1, raw.length) : raw;
    }

    private static CertifiedKey with(CertifiedKey k, String purpose, String alg, String format, Jwk jwk) {
        return new CertifiedKey(k.deviceId(), k.keyId(), purpose, alg, format, jwk, k.hardwareBound(), k.certifiedAt());
    }

    // ── ECDH-ES ────────────────────────────────────────────────────────────

    @Test
    void ecKeyTwoEncryptionsDifferAndBothOpen() throws Exception {
        Fixture f = ec();
        String a = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT);
        String b = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT);

        assertNotEquals(a, b);
        assertArrayEquals(PLAINTEXT, ReferenceDecryptor.open(a, f.priv(), true));
        assertArrayEquals(PLAINTEXT, ReferenceDecryptor.open(b, f.priv(), true));
    }

    @Test
    void ecHeaderIsExactlyAlgEncEpk() throws Exception {
        String jwe = DeviceEncryption.encryptToDevice(ec().key(), PLAINTEXT);
        String[] parts = jwe.split("\\.", -1);
        assertEquals(5, parts.length);
        String header = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
        JsonNode node = new ObjectMapper().readTree(header);

        assertEquals(List.of("alg", "enc", "epk"), names(node));
        assertEquals(List.of("kty", "crv", "x", "y"), names(node.get("epk")));
        String x = node.get("epk").get("x").asText();
        String y = node.get("epk").get("y").asText();
        assertEquals("{\"alg\":\"ECDH-ES\",\"enc\":\"A256GCM\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x
                + "\",\"y\":\"" + y + "\"}}", header);
        assertEquals(32, B64D.decode(x).length);
        assertEquals(32, B64D.decode(y).length);
        assertEquals("", parts[1]);
        assertEquals(12, B64D.decode(parts[2]).length);
        assertEquals(PLAINTEXT.length, B64D.decode(parts[3]).length);
        assertEquals(16, B64D.decode(parts[4]).length);
    }

    // ── RSA-OAEP-256 ───────────────────────────────────────────────────────

    @Test
    void rsaKeyTwoEncryptionsDifferAndBothOpen() throws Exception {
        Fixture f = rsa(2048);
        String a = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT);
        String b = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT);

        assertNotEquals(a, b);
        assertArrayEquals(PLAINTEXT, ReferenceDecryptor.open(a, f.priv(), true));
        assertArrayEquals(PLAINTEXT, ReferenceDecryptor.open(b, f.priv(), true));
    }

    @Test
    void rsaHeaderAndOaepSha256WithMgf1Sha256() throws Exception {
        Fixture f = rsa(2048);
        String[] parts = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT).split("\\.", -1);

        assertEquals("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}", new String(B64D.decode(parts[0]), StandardCharsets.UTF_8));
        byte[] encryptedKey = B64D.decode(parts[1]);
        assertEquals(256, encryptedKey.length);
        assertEquals(32, ReferenceDecryptor.unwrap(encryptedKey, f.priv(), MGF1ParameterSpec.SHA256).length);
        assertThrows(GeneralSecurityException.class, () -> ReferenceDecryptor.unwrap(encryptedKey, f.priv(), MGF1ParameterSpec.SHA1));
    }

    // ── AAD is the protected header ────────────────────────────────────────

    @Test
    void headerEditedAfterSealingDoesNotOpen() throws Exception {
        for (Fixture f : List.of(ec(), rsa(2048))) {
            String[] parts = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT).split("\\.", -1);
            // Equivalent JSON, different bytes: the AAD must be the bytes.
            String edited = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8).replace("\"enc\":", "\"enc\": ");
            parts[0] = B64.encodeToString(edited.getBytes(StandardCharsets.UTF_8));
            String jwe = String.join(".", parts);
            assertThrows(GeneralSecurityException.class, () -> ReferenceDecryptor.open(jwe, f.priv(), false), f.key().alg());
        }
    }

    // ── Refusals ───────────────────────────────────────────────────────────

    @Test
    void aSignKeyIsRefused() throws Exception {
        CertifiedKey dec = ec().key();
        CertifiedKey sign = with(dec, KeyChallengeOptions.PURPOSE_SIGN, "ES256", null, dec.jwk());
        CertifiedKey signWithJwe = with(dec, KeyChallengeOptions.PURPOSE_SIGN, "ES256", "jwe", dec.jwk());
        CertifiedKey decryptWithSignAlg = with(dec, KeyChallengeOptions.PURPOSE_DECRYPT, "ES256", "jwe", dec.jwk());

        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(sign, PLAINTEXT));
        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(signWithJwe, PLAINTEXT));
        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(decryptWithSignAlg, PLAINTEXT));
    }

    @Test
    void anAppleEciesKeyIsRefusedByName() throws Exception {
        CertifiedKey dec = ec().key();
        CertifiedKey apple = with(dec, KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", "apple-ecies", dec.jwk());

        EnvelopeFormatNotSupportedException ex = assertThrows(EnvelopeFormatNotSupportedException.class,
                () -> DeviceEncryption.encryptToDevice(apple, PLAINTEXT));
        assertEquals("apple-ecies", ex.format());
        assertTrue(ex.getMessage().contains("apple-ecies"));
        assertTrue(ex instanceof IllegalArgumentException);
    }

    @Test
    void aDecryptKeyWithoutAFormatIsRefused() throws Exception {
        CertifiedKey dec = ec().key();
        CertifiedKey noFormat = with(dec, KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", null, dec.jwk());
        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(noFormat, PLAINTEXT));
    }

    @Test
    void aP384KeyIsRefused() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp384r1"));
        ECPublicKey pub = (ECPublicKey) gen.generateKeyPair().getPublic();
        Jwk jwk = new Jwk("EC", "P-384", B64.encodeToString(DeviceEncryption.fixed(pub.getW().getAffineX(), 48)),
                B64.encodeToString(DeviceEncryption.fixed(pub.getW().getAffineY(), 48)));
        CertifiedKey key = key(KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", "jwe", jwk);

        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(key, PLAINTEXT));
    }

    @Test
    void ecCoordinatesThatAreNot32BytesAreRefused() throws Exception {
        CertifiedKey dec = ec().key();
        for (int length : new int[] {31, 33}) {
            Jwk jwk = Jwk.ec(B64.encodeToString(new byte[length]), dec.jwk().y());
            CertifiedKey key = with(dec, KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", "jwe", jwk);
            assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(key, PLAINTEXT), length + " bytes");
        }
    }

    @Test
    void anEcPointOffTheCurveIsRefused() throws Exception {
        CertifiedKey dec = ec().key();
        byte[] y = B64D.decode(dec.jwk().y());
        y[31] ^= 1;
        CertifiedKey key = with(dec, KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", "jwe", Jwk.ec(dec.jwk().x(), B64.encodeToString(y)));

        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(key, PLAINTEXT));
    }

    @Test
    void aShortRsaModulusIsRefused() throws Exception {
        CertifiedKey key = rsa(1024).key();
        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(key, PLAINTEXT));
    }

    @Test
    void aMismatchedAlgAndKtyIsRefused() throws Exception {
        CertifiedKey ec = ec().key();
        CertifiedKey rsa = rsa(2048).key();
        CertifiedKey ecWithRsaAlg = with(ec, KeyChallengeOptions.PURPOSE_DECRYPT, "RSA-OAEP-256", "jwe", ec.jwk());
        CertifiedKey rsaWithEcAlg = with(rsa, KeyChallengeOptions.PURPOSE_DECRYPT, "ECDH-ES", "jwe", rsa.jwk());

        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(ecWithRsaAlg, PLAINTEXT));
        assertThrows(IllegalArgumentException.class, () -> DeviceEncryption.encryptToDevice(rsaWithEcAlg, PLAINTEXT));
    }

    // ── Determinism through the seam ───────────────────────────────────────

    @Test
    void theSeamMakesTheEnvelopeReproducible() throws Exception {
        Fixture f = ec();
        KeyPair eph = p256Pair();
        String a = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT, () -> eph, new CountingRandom());
        String b = DeviceEncryption.encryptToDevice(f.key(), PLAINTEXT, () -> eph, new CountingRandom());

        assertEquals(a, b);
        assertArrayEquals(PLAINTEXT, ReferenceDecryptor.open(a, f.priv(), true));
    }

    private static List<String> names(JsonNode node) {
        List<String> out = new ArrayList<>();
        for (Iterator<String> it = node.fieldNames(); it.hasNext();) {
            out.add(it.next());
        }
        return out;
    }

    /** Yields 1, 2, 3, … so a seeded run is reproducible. */
    static final class CountingRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;

        @Override
        public void nextBytes(byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) (i + 1);
            }
        }
    }

    /**
     * The device's parser in software: a whitelist over the header, fixed
     * sizes, the header as AAD, and the same Concat KDF. With strict false the
     * header members are not checked, so an edited header can be tried against
     * the tag.
     */
    static final class ReferenceDecryptor {
        static byte[] open(String compact, PrivateKey recipient, boolean strict) throws Exception {
            String[] parts = compact.split("\\.", -1);
            if (parts.length != 5) {
                throw new IllegalArgumentException(parts.length + " segments");
            }
            JsonNode header = new ObjectMapper().readTree(B64D.decode(parts[0]));
            if (!"A256GCM".equals(header.path("enc").asText())) {
                throw new IllegalArgumentException("enc");
            }
            byte[] iv = B64D.decode(parts[2]);
            byte[] ciphertext = B64D.decode(parts[3]);
            byte[] tag = B64D.decode(parts[4]);
            if (iv.length != 12 || tag.length != 16) {
                throw new IllegalArgumentException("iv/tag size");
            }
            byte[] cek;
            if ("EC".equals(recipient.getAlgorithm())) {
                if (strict && !names(header).equals(List.of("alg", "enc", "epk"))) {
                    throw new IllegalArgumentException("header members " + names(header));
                }
                if (!"ECDH-ES".equals(header.path("alg").asText()) || !parts[1].isEmpty()) {
                    throw new IllegalArgumentException("alg or encrypted key");
                }
                JsonNode epk = header.get("epk");
                if (strict && !names(epk).equals(List.of("kty", "crv", "x", "y"))) {
                    throw new IllegalArgumentException("epk members " + names(epk));
                }
                if (!"EC".equals(epk.path("kty").asText()) || !"P-256".equals(epk.path("crv").asText())) {
                    throw new IllegalArgumentException("epk");
                }
                byte[] x = B64D.decode(epk.get("x").asText());
                byte[] y = B64D.decode(epk.get("y").asText());
                if (x.length != 32 || y.length != 32) {
                    throw new IllegalArgumentException("epk coordinates");
                }
                AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                params.init(new ECGenParameterSpec("secp256r1"));
                ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
                ECPublicKey eph = (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                        new ECPublicKeySpec(new ECPoint(new BigInteger(1, x), new BigInteger(1, y)), spec));
                KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
                agreement.init(recipient);
                agreement.doPhase(eph, true);
                cek = DeviceEncryption.concatKdf(DeviceEncryption.fixed(new BigInteger(1, agreement.generateSecret()), 32));
            } else {
                if (strict && !names(header).equals(List.of("alg", "enc"))) {
                    throw new IllegalArgumentException("header members " + names(header));
                }
                if (!"RSA-OAEP-256".equals(header.path("alg").asText())) {
                    throw new IllegalArgumentException("alg");
                }
                cek = unwrap(B64D.decode(parts[1]), recipient, MGF1ParameterSpec.SHA256);
            }
            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
            gcm.updateAAD(parts[0].getBytes(StandardCharsets.US_ASCII));
            byte[] sealed = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
            System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);
            return gcm.doFinal(sealed);
        }

        static byte[] unwrap(byte[] encryptedKey, PrivateKey recipient, MGF1ParameterSpec mgf1) throws GeneralSecurityException {
            Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPPadding");
            oaep.init(Cipher.DECRYPT_MODE, recipient, new OAEPParameterSpec("SHA-256", "MGF1", mgf1, PSource.PSpecified.DEFAULT));
            return oaep.doFinal(encryptedKey);
        }
    }
}
