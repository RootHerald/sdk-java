package io.rootherald.client;

/**
 * The key's {@code format} is one {@link DeviceEncryption#encryptToDevice(CertifiedKey, byte[])}
 * cannot produce: {@code apple-ecies}, the Security.framework ECIES envelope a
 * macOS enclave key opens, needs an Apple-side encryptor.
 */
public final class EnvelopeFormatNotSupportedException extends IllegalArgumentException {

    private static final long serialVersionUID = 1L;

    private final String format;

    public EnvelopeFormatNotSupportedException(String format) {
        super("key format \"" + format + "\" is not produced here: encryptToDevice writes the jwe envelope a TPM"
                + " decrypt key opens; an apple-ecies key needs an Apple-side encryptor");
        this.format = format;
    }

    /** The key's {@code format}. */
    public String format() {
        return format;
    }
}
