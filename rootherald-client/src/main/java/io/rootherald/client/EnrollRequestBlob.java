package io.rootherald.client;

import java.util.ArrayList;
import java.util.List;

/**
 * {@code EnrollBegin()} output — the body of {@code POST /api/v1/devices/enroll}.
 * <p>
 * Produced by the customer's keyless client and relayed verbatim by the
 * customer's backend via {@link BackgroundCheckClient#relayEnroll(EnrollRequestBlob)}.
 * The field names are the canonical JSON keys the native client emits and the
 * RootHerald server binds; mirrors {@code @rootherald/contracts}'
 * {@code EnrollRequestBlob}.
 *
 * @param ekPublicKey         base64 platform-native EK public blob — the stable
 *                            hardware anchor the {@code deviceId} is derived from (required)
 * @param akPublicArea        base64 {@code TPM2B_PUBLIC} of the freshly-created AK (required)
 * @param platform            reporting platform, e.g. {@code "windows" | "linux" | "macos"}
 * @param ekCertPem           PEM-encoded EK certificate, or {@code null} (firmware TPMs
 *                            may ship no NV-stored EK cert)
 * @param ekCertificateChain  PEM-encoded intermediate CA certs recovered locally, or
 *                            {@code null}. Defensively copied; order is not significant.
 */
public record EnrollRequestBlob(
        String ekPublicKey,
        String akPublicArea,
        String platform,
        String ekCertPem,
        List<String> ekCertificateChain) {

    public EnrollRequestBlob {
        if (ekPublicKey == null || ekPublicKey.isEmpty()) {
            throw new IllegalArgumentException("ekPublicKey is required");
        }
        if (akPublicArea == null || akPublicArea.isEmpty()) {
            throw new IllegalArgumentException("akPublicArea is required");
        }
        ekCertificateChain = ekCertificateChain == null ? null : List.copyOf(ekCertificateChain);
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Builder for {@link EnrollRequestBlob}; the two optional cert fields default to absent. */
    public static final class Builder {
        private String ekPublicKey;
        private String akPublicArea;
        private String platform;
        private String ekCertPem;
        private List<String> ekCertificateChain;

        /** base64 platform-native EK public blob (required). */
        public Builder ekPublicKey(String ekPublicKey) {
            this.ekPublicKey = ekPublicKey;
            return this;
        }

        /** base64 {@code TPM2B_PUBLIC} of the AK (required). */
        public Builder akPublicArea(String akPublicArea) {
            this.akPublicArea = akPublicArea;
            return this;
        }

        /** Reporting platform, e.g. {@code "windows"}. */
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

        public EnrollRequestBlob build() {
            return new EnrollRequestBlob(ekPublicKey, akPublicArea, platform, ekCertPem, ekCertificateChain);
        }
    }
}
