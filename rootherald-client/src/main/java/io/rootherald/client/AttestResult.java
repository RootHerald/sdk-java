package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * The result of {@link BackgroundCheckClient#attest(String, AttestOptions)}:
 * the device verdict, the full verdict node, and an optional signed EAT (JWT)
 * when {@link AttestOptions#returnToken(boolean)} was requested.
 *
 * @param verdict     normalised verdict: {@code "allow"}, {@code "deny"}, or {@code "review"}
 * @param verdictNode the full verdict object returned by the server
 * @param token       the signed EAT, or {@code null} if not requested/returned
 */
public record AttestResult(String verdict, JsonNode verdictNode, String token) {

    /** True when the verdict is {@code "allow"}. */
    public boolean isAllowed() {
        return "allow".equalsIgnoreCase(verdict);
    }

    /**
     * Map the flat "verdict" the server emits ("pass"/"fail"/"warn") to the
     * normalised SDK vocabulary. Unknown/missing values map to {@code "review"}
     * (fail-closed: never silently {@code "allow"}).
     */
    static String normalize(String raw) {
        if (raw == null) {
            return "review";
        }
        return switch (raw.trim().toLowerCase()) {
            case "pass", "allow", "affirming" -> "allow";
            case "fail", "deny", "contraindicated" -> "deny";
            default -> "review";
        };
    }
}
