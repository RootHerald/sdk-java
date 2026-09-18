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
 *   <li>{@code "windows"} / {@code "linux"}: {@code ekPublicKey} and
 *       {@code akPublicArea}; optionally {@code ekCertPem},
 *       {@code ekCertificateChain} and {@code tpmSelfReport}</li>
 *   <li>{@code "macos"}: {@code ekPublicKey} and {@code akPublicArea}, both the
 *       Secure Enclave key (X9.63 uncompressed, base64)</li>
 *   <li>{@code "ios"}: {@code iosKeyId}, {@code iosAttestationObject} and
 *       {@code nonce}; the enrollment completes in this one leg</li>
 * </ul>
 *
 * @param ekPublicKey          base64 platform-native EK public blob; on macOS the
 *                             enclave key. Required on a TPM or macOS body
 * @param akPublicArea         base64 {@code TPM2B_PUBLIC} of the freshly-created AK;
 *                             on macOS the same key as {@code ekPublicKey}. Required
 *                             on a TPM or macOS body
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
        String akPublicArea,
        String platform,
        String ekCertPem,
        List<String> ekCertificateChain,
        TpmSelfReport tpmSelfReport,
        String iosKeyId,
        String iosAttestationObject,
        String nonce) {

    /** The App Attest platform, the one body with no EK or AK. */
    public static final String PLATFORM_IOS = "ios";

    public EnrollRequestBlob {
        if (platform == null || platform.isEmpty()) {
            throw new IllegalArgumentException("platform is required");
        }
        if (PLATFORM_IOS.equals(platform)) {
            requireText(iosKeyId, "iosKeyId");
            requireText(iosAttestationObject, "iosAttestationObject");
            requireText(nonce, "nonce");
        } else {
            requireText(ekPublicKey, "ekPublicKey");
            requireText(akPublicArea, "akPublicArea");
        }
        ekCertificateChain = ekCertificateChain == null ? null : List.copyOf(ekCertificateChain);
    }

    /** A TPM or Secure Enclave body: the fields of the pre-iOS record. */
    public EnrollRequestBlob(String ekPublicKey, String akPublicArea, String platform,
                             String ekCertPem, List<String> ekCertificateChain) {
        this(ekPublicKey, akPublicArea, platform, ekCertPem, ekCertificateChain, null, null, null, null);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link EnrollRequestBlob}; every optional field defaults to absent. */
    public static final class Builder {
        private String ekPublicKey;
        private String akPublicArea;
        private String platform;
        private String ekCertPem;
        private List<String> ekCertificateChain;
        private TpmSelfReport tpmSelfReport;
        private String iosKeyId;
        private String iosAttestationObject;
        private String nonce;

        /** base64 platform-native EK public blob (TPM and macOS). */
        public Builder ekPublicKey(String ekPublicKey) {
            this.ekPublicKey = ekPublicKey;
            return this;
        }

        /** base64 {@code TPM2B_PUBLIC} of the AK (TPM and macOS). */
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
            return new EnrollRequestBlob(ekPublicKey, akPublicArea, platform, ekCertPem, ekCertificateChain,
                    tpmSelfReport, iosKeyId, iosAttestationObject, nonce);
        }
    }
}
