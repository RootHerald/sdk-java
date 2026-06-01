package io.rootherald.client;

import io.rootherald.AttestationClaims;

/**
 * Outcome of a verification call.
 *
 * @param verdict  one of {@code allow}, {@code deny}, {@code review} (server-decided)
 * @param reason   short human-readable rationale
 * @param riskScore optional numeric risk score (0..1; -1 if absent)
 * @param claims   decoded attestation claims when verdict != {@code deny}
 */
public record VerifyResult(String verdict, String reason, double riskScore, AttestationClaims claims) {
    public boolean isAllowed() {
        return "allow".equalsIgnoreCase(verdict);
    }
}
