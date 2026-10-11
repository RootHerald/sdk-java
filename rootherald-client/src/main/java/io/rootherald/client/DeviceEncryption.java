package io.rootherald.client;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.function.Supplier;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts to a {@link CertifiedKey} minted with
 * {@link KeyChallengeOptions#PURPOSE_DECRYPT}, using only the JCA.
 * <p>
 * The result is the one JWE compact serialization the device's
 * {@code RootHeraldDecrypt} opens: {@code ECDH-ES} with the Concat KDF
 * (RFC 7518 §4.6: AlgorithmID the enc name, PartyU and PartyV empty, 256-bit
 * key) and a fresh ephemeral P-256 key per call for an EC key,
 * {@code RSA-OAEP-256} (OAEP SHA-256, MGF1-SHA-256) wrapping a random 32-byte
 * CEK for an RSA key, {@code A256GCM} for both with the protected header as
 * the additional data. The header carries {@code alg}, {@code enc} and
 * ({@code ECDH-ES} only) {@code epk}, nothing else, because the device
 * refuses any other member rather than ignoring it.
 * <p>
 * Encryption uses the public half, so anyone holding the JWK can encrypt to
 * the device; what the chip guarantees is that only it can open the result.
 */
public final class DeviceEncryption {

    static final String ALG_ECDH_ES = "ECDH-ES";
    static final String ALG_RSA_OAEP_256 = "RSA-OAEP-256";
    static final String ENC_A256GCM = "A256GCM";
    static final String FORMAT_JWE = "jwe";

    private static final int COORDINATE_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final int CEK_BYTES = 32;
    private static final int MIN_RSA_MODULUS_BITS = 2048;

    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private DeviceEncryption() {
    }

    /**
     * @param key       the decrypt key, as {@link RootHeraldClient#certifyKey(String, String)} returned it
     * @param plaintext the bytes only the device may read
     * @return the JWE compact serialization to send to the device
     * @throws IllegalArgumentException for a key that cannot open the result: a sign key,
     *                                  a key without a format, a curve other than P-256,
     *                                  a coordinate that is not 32 bytes, or an RSA
     *                                  modulus under 2048 bits
     * @throws EnvelopeFormatNotSupportedException for an {@code apple-ecies} key, which a
     *                                  macOS enclave opens and needs an Apple-side encryptor
     */
    public static String encryptToDevice(CertifiedKey key, byte[] plaintext) {
        return encryptToDevice(key, plaintext, DeviceEncryption::freshEphemeral, new SecureRandom());
    }

    /**
     * The seam the known-answer tests inject the ephemeral key, CEK, OAEP
     * seed and IV through: {@code random} is asked for the CEK (32 bytes,
     * RSA only), then by the OAEP cipher for its seed, then for the IV.
     */
    static String encryptToDevice(CertifiedKey key, byte[] plaintext, Supplier<KeyPair> ephemeral, SecureRandom random) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(plaintext, "plaintext");
        if (!KeyChallengeOptions.PURPOSE_DECRYPT.equals(key.purpose())) {
            throw new IllegalArgumentException("key purpose is \"" + key.purpose() + "\"; only a decrypt key opens an envelope");
        }
        if (key.format() == null) {
            throw new IllegalArgumentException("key has no envelope format; a decrypt key names jwe or apple-ecies");
        }
        if (!FORMAT_JWE.equals(key.format())) {
            throw new EnvelopeFormatNotSupportedException(key.format());
        }
        Jwk jwk = Objects.requireNonNull(key.jwk(), "key.jwk");
        if (jwk.isEc() && ALG_ECDH_ES.equals(key.alg())) {
            return encryptEcdhEs(jwk, plaintext, ephemeral, random);
        }
        if (jwk.isRsa() && ALG_RSA_OAEP_256.equals(key.alg())) {
            return encryptRsaOaep(jwk, plaintext, random);
        }
        throw new IllegalArgumentException("key alg \"" + key.alg() + "\" with kty \"" + jwk.kty()
                + "\" is not ECDH-ES on an EC key or RSA-OAEP-256 on an RSA key");
    }

    private static String encryptEcdhEs(Jwk jwk, byte[] plaintext, Supplier<KeyPair> ephemeral, SecureRandom random) {
        if (!Jwk.CRV_P256.equals(jwk.crv())) {
            throw new IllegalArgumentException("jwk.crv \"" + jwk.crv() + "\" is not P-256; no device certifies another curve");
        }
        BigInteger x = new BigInteger(1, coordinate(jwk.x(), "x"));
        BigInteger y = new BigInteger(1, coordinate(jwk.y(), "y"));
        PublicKey recipient;
        try {
            recipient = KeySignatures.ecPublicKey(x, y);
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("jwk is not a usable P-256 public key: " + ex.getMessage(), ex);
        }
        try {
            KeyPair eph = ephemeral.get();
            KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
            agreement.init(eph.getPrivate());
            agreement.doPhase(recipient, true);
            byte[] z = fixed(new BigInteger(1, agreement.generateSecret()), COORDINATE_BYTES);
            byte[] cek = concatKdf(z);
            Arrays.fill(z, (byte) 0);

            ECPublicKey epk = (ECPublicKey) eph.getPublic();
            String header = "{\"alg\":\"" + ALG_ECDH_ES + "\",\"enc\":\"" + ENC_A256GCM
                    + "\",\"epk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\""
                    + BASE64URL.encodeToString(fixed(epk.getW().getAffineX(), COORDINATE_BYTES))
                    + "\",\"y\":\"" + BASE64URL.encodeToString(fixed(epk.getW().getAffineY(), COORDINATE_BYTES))
                    + "\"}}";
            return seal(header, new byte[0], cek, plaintext, random);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("ECDH-ES envelope: " + ex.getMessage(), ex);
        }
    }

    private static String encryptRsaOaep(Jwk jwk, byte[] plaintext, SecureRandom random) {
        BigInteger n = new BigInteger(1, base64Url(jwk.n(), "n"));
        BigInteger e = new BigInteger(1, base64Url(jwk.e(), "e"));
        if (n.bitLength() < MIN_RSA_MODULUS_BITS) {
            throw new IllegalArgumentException("jwk.n must be a modulus of at least " + MIN_RSA_MODULUS_BITS
                    + " bits (got " + n.bitLength() + ")");
        }
        PublicKey recipient;
        try {
            recipient = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        } catch (GeneralSecurityException | IllegalArgumentException ex) {
            throw new IllegalArgumentException("jwk is not a usable RSA public key: " + ex.getMessage(), ex);
        }
        try {
            byte[] cek = new byte[CEK_BYTES];
            random.nextBytes(cek);
            // "OAEPWithSHA-256AndMGF1Padding" alone leaves MGF1 on SHA-1 under
            // SunJCE; the spec pins both digests to what the device expects.
            Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPPadding");
            oaep.init(Cipher.ENCRYPT_MODE, recipient,
                    new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT),
                    random);
            byte[] encryptedKey = oaep.doFinal(cek);
            String header = "{\"alg\":\"" + ALG_RSA_OAEP_256 + "\",\"enc\":\"" + ENC_A256GCM + "\"}";
            return seal(header, encryptedKey, cek, plaintext, random);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("RSA-OAEP-256 envelope: " + ex.getMessage(), ex);
        }
    }

    private static String seal(String header, byte[] encryptedKey, byte[] cek, byte[] plaintext, SecureRandom random)
            throws GeneralSecurityException {
        String protectedHeader = BASE64URL.encodeToString(header.getBytes(StandardCharsets.UTF_8));
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(TAG_BITS, iv));
        gcm.updateAAD(protectedHeader.getBytes(StandardCharsets.US_ASCII));
        byte[] sealed = gcm.doFinal(plaintext);
        Arrays.fill(cek, (byte) 0);
        int tagBytes = TAG_BITS / 8;
        byte[] ciphertext = Arrays.copyOfRange(sealed, 0, sealed.length - tagBytes);
        byte[] tag = Arrays.copyOfRange(sealed, sealed.length - tagBytes, sealed.length);
        return protectedHeader + "." + BASE64URL.encodeToString(encryptedKey) + "." + BASE64URL.encodeToString(iv)
                + "." + BASE64URL.encodeToString(ciphertext) + "." + BASE64URL.encodeToString(tag);
    }

    /**
     * Concat KDF, one round: SHA-256(counter ‖ Z ‖ AlgorithmID ‖ PartyUInfo ‖
     * PartyVInfo ‖ SuppPubInfo), each info field length-prefixed, keydatalen 256.
     */
    static byte[] concatKdf(byte[] z) throws GeneralSecurityException {
        byte[] alg = ENC_A256GCM.getBytes(StandardCharsets.US_ASCII);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        sha256.update(new byte[] {0, 0, 0, 1});
        sha256.update(z);
        sha256.update(new byte[] {0, 0, 0, (byte) alg.length});
        sha256.update(alg);
        sha256.update(new byte[] {0, 0, 0, 0});
        sha256.update(new byte[] {0, 0, 0, 0});
        sha256.update(new byte[] {0, 0, 1, 0});
        return sha256.digest();
    }

    private static KeyPair freshEphemeral() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
            gen.initialize(new ECGenParameterSpec("secp256r1"));
            return gen.generateKeyPair();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("P-256 is unavailable: " + ex.getMessage(), ex);
        }
    }

    private static byte[] coordinate(String value, String field) {
        byte[] raw = base64Url(value, field);
        if (raw.length != COORDINATE_BYTES) {
            throw new IllegalArgumentException("jwk." + field + " must decode to exactly " + COORDINATE_BYTES
                    + " bytes (got " + raw.length + ")");
        }
        return raw;
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

    /** Big-endian, unsigned, exactly {@code length} bytes. */
    static byte[] fixed(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        if (raw.length == length) {
            return raw;
        }
        byte[] out = new byte[length];
        if (raw.length > length) {
            System.arraycopy(raw, raw.length - length, out, 0, length);
        } else {
            System.arraycopy(raw, 0, out, length - raw.length, raw.length);
        }
        return out;
    }
}
