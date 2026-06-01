package io.rootherald;

import java.util.Map;
import java.util.Optional;

/**
 * Device-specific claims pulled out of an attestation token.
 *
 * @param ueid        EAT Universal Entity ID (base64; typically EK cert fingerprint)
 * @param hwmodel     Hardware model string, when known
 * @param dbgstat     Debug status (EAT-RFC 9711 §5.4); "3" means not-disabled-current
 * @param earStatus   Attestation Results for Secure Interactions (AR4SI) status code
 * @param raw         Raw additional claims map (jackson-decoded; useful for forwards compat)
 */
public record DeviceClaims(
        String ueid,
        String hwmodel,
        String dbgstat,
        Integer earStatus,
        Map<String, Object> raw
) {
    public Optional<String> hardwareModel() {
        return Optional.ofNullable(hwmodel);
    }
}
