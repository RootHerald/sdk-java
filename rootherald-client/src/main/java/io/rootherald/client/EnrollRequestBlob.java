package io.rootherald.client;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code EnrollBegin()} output — the body of {@code POST /api/v1/attest/enroll},
 * discriminated by {@code platform}.
 * <p>
 * Produced by the customer's keyless client and relayed verbatim by the
 * customer's backend via {@link RootHeraldClient#relayEnroll(EnrollRequestBlob)}.
 * The field names are the canonical JSON keys the native client emits and the
 * RootHerald server binds; every field that is set is sent and nothing else is.
 * A backend that already holds the client's JSON should prefer
 * {@link RootHeraldClient#relayEnroll(String)}, which relays it byte-for-byte.
 * <p>
 * Which fields a platform requires:
 * <ul>
 *   <li>{@code "windows"} / {@code "linux"}: {@code ekPublicKey} and the nested
 *       {@code attestationKey}; optionally {@code ekCertPem},
 *       {@code ekCertificateChain} and {@code tpmSelfReport}. The nested object
 *       is what tells an 8.0 body from a 7.0 one; a flat {@code akPublicArea}
 *       on a TPM body is refused here, before any request</li>
 *   <li>{@code "macos"}: {@code ekPublicKey} and {@code akPublicArea}, both the
 *       Secure Enclave key (X9.63 uncompressed, base64); the body stays flat
 *       because there is no parent</li>
 *   <li>{@code "ios"}: {@code iosKeyId}, {@code iosAttestationObject} and
 *       {@code nonce}; the enrollment completes in this one leg</li>
 * </ul>
 *
 * @param ekPublicKey          base64 {@code TPM2B_PUBLIC} of the endorsement key; on macOS
 *                             the enclave key. Required on a TPM or macOS body
 * @param attestationKey       this installation's attestation key and its parent.
 *                             Required on a TPM body; absent otherwise
 * @param akPublicArea         on macOS, the same key as {@code ekPublicKey}. Required on
 *                             a macOS body; absent otherwise
 * @param platform             reporting platform, {@code "windows" | "linux" | "macos" | "ios"}.
 *                             Required
 * @param ekCertPem            PEM-encoded EK certificate, or {@code null} (firmware TPMs
 *                             may ship no NV-stored EK cert)
 * @param ekCertificateChain   PEM-encoded intermediate CA certs recovered locally, or
 *                             {@code null}. Defensively copied; order is not significant
 * @param tpmSelfReport        the TPM's unsigned self-report, or {@code null}
 * @param iosKeyId             base64 App Attest key id. Required on an iOS body
 * @param iosAttestationObject base64 CBOR App Attest attestation object. Required on
 *                             an iOS body
 * @param nonce                the challenge handle the attestation was made over
 *                             (base64url, unpadded). Required on an iOS body
 */
public record EnrollRequestBlob(
        String ekPublicKey,
        AttestationKey attestationKey,
        String akPublicArea,
        String platform,
        String ekCertPem,
        List<String> ekCertificateChain,
        TpmSelfReport tpmSelfReport,
        String iosKeyId,
        String iosAttestationObject,
        String nonce) {

    public static final String PLATFORM_WINDOWS = "windows";
    public static final String PLATFORM_LINUX = "linux";
    public static final String PLATFORM_MACOS = "macos";
    /** The App Attest platform, the one body with no EK or AK. */
    public static final String PLATFORM_IOS = "ios";

    public EnrollRequestBlob {
        if (platform == null || platform.isEmpty()) {
            throw new IllegalArgumentException("platform is required");
        }
        switch (platform) {
            case PLATFORM_WINDOWS, PLATFORM_LINUX -> {
                requireText(ekPublicKey, "ekPublicKey");
                if (attestationKey == null) {
                    throw new IllegalArgumentException(
                            "attestationKey { publicArea, parentPublicArea, qualifiedName } is required on a "
                                    + platform + " body");
                }
                requireAbsent(akPublicArea, "akPublicArea", platform);
            }
            case PLATFORM_MACOS -> {
                requireText(ekPublicKey, "ekPublicKey");
                requireText(akPublicArea, "akPublicArea");
                if (attestationKey != null) {
                    throw new IllegalArgumentException("attestationKey is not part of a macos body");
                }
            }
            case PLATFORM_IOS -> {
                requireText(iosKeyId, "iosKeyId");
                requireText(iosAttestationObject, "iosAttestationObject");
                requireText(nonce, "nonce");
            }
            default -> throw new IllegalArgumentException(
                    "platform must be windows, linux, macos or ios (got " + platform + ")");
        }
        ekCertificateChain = ekCertificateChain == null ? null : List.copyOf(ekCertificateChain);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    private static void requireAbsent(String value, String field, String platform) {
        if (value != null) {
            throw new IllegalArgumentException(field + " is the 7.0 shape; a " + platform
                    + " body carries attestationKey { publicArea, parentPublicArea, qualifiedName }");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link EnrollRequestBlob}; every optional field defaults to absent. */
    public static final class Builder {
        private String ekPublicKey;
        private AttestationKey attestationKey;
        private String akPublicArea;
        private String platform;
        private String ekCertPem;
        private List<String> ekCertificateChain;
        private TpmSelfReport tpmSelfReport;
        private String iosKeyId;
        private String iosAttestationObject;
        private String nonce;

        /** base64 EK public area (TPM), or the enclave key (macOS). */
        public Builder ekPublicKey(String ekPublicKey) {
            this.ekPublicKey = ekPublicKey;
            return this;
        }

        /** This installation's attestation key and its parent (TPM). */
        public Builder attestationKey(AttestationKey attestationKey) {
            this.attestationKey = attestationKey;
            return this;
        }

        /** This installation's attestation key and its parent (TPM). */
        public Builder attestationKey(String publicArea, String parentPublicArea, String qualifiedName) {
            return attestationKey(new AttestationKey(publicArea, parentPublicArea, qualifiedName));
        }

        /** The enclave key again (macOS only). */
        public Builder akPublicArea(String akPublicArea) {
            this.akPublicArea = akPublicArea;
            return this;
        }

        /** Reporting platform, e.g. {@code "windows"}. Required. */
        public Builder platform(String platform) {
            this.platform = platform;
            return this;
        }

        /** PEM-encoded EK certificate (optional). */
        public Builder ekCertPem(String ekCertPem) {
            this.ekCertPem = ekCertPem;
            return this;
        }

        /** Replace the EK intermediate-cert chain (optional). */
        public Builder ekCertificateChain(List<String> chain) {
            this.ekCertificateChain = chain == null ? null : new ArrayList<>(chain);
            return this;
        }

        /** Append one PEM-encoded intermediate cert to the chain. */
        public Builder addEkCertificate(String pem) {
            if (this.ekCertificateChain == null) {
                this.ekCertificateChain = new ArrayList<>();
            }
            this.ekCertificateChain.add(pem);
            return this;
        }

        /** The TPM's unsigned self-report (optional). */
        public Builder tpmSelfReport(TpmSelfReport tpmSelfReport) {
            this.tpmSelfReport = tpmSelfReport;
            return this;
        }

        /** The TPM's unsigned self-report (optional). */
        public Builder tpmSelfReport(String manufacturer, String vendorString) {
            return tpmSelfReport(new TpmSelfReport(manufacturer, vendorString));
        }

        /** base64 App Attest key id (iOS). */
        public Builder iosKeyId(String iosKeyId) {
            this.iosKeyId = iosKeyId;
            return this;
        }

        /** base64 CBOR App Attest attestation object (iOS). */
        public Builder iosAttestationObject(String iosAttestationObject) {
            this.iosAttestationObject = iosAttestationObject;
            return this;
        }

        /** The challenge handle the attestation was made over (iOS). */
        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public EnrollRequestBlob build() {
            return new EnrollRequestBlob(ekPublicKey, attestationKey, akPublicArea, platform, ekCertPem,
                    ekCertificateChain, tpmSelfReport, iosKeyId, iosAttestationObject, nonce);
        }
    }
}
