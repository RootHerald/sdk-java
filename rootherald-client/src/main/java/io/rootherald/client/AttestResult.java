package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The result of {@link BackgroundCheckClient#verify(String, AttestOptions)}:
 * the device verdict and the full verdict node.
 *
 * @param verdict     normalised verdict: {@code "allow"}, {@code "deny"}, or {@code "review"}
 * @param verdictNode the full verdict object returned by the server
 */
public record AttestResult(String verdict, JsonNode verdictNode) {

    /** True when the verdict is {@code "allow"}. */
    public boolean isAllowed() {
        return "allow".equalsIgnoreCase(verdict);
    }

    /**
     * The raw {@code device} sub-object of the verdict, or a missing node. The
     * cohort getters below read from here.
     */
    private JsonNode device() {
        return verdictNode == null ? null : verdictNode.path("device");
    }

    /**
     * Opaque cohort key, or {@code null} if the server did not return one.
     * <p>
     * Cohort fields are ADDITIVE and advisory only (never a trust gate). The
     * server populates them on {@code verdict.device} (camelCase) when a
     * quote-bound event log was supplied, and omits them otherwise.
     */
    public String cohortKey() {
        JsonNode d = device();
        return d != null && d.hasNonNull("cohortKey") ? d.get("cohortKey").asText() : null;
    }

    /** Cohort comparison scope ({@code "global"} | {@code "tenant-fleet"}), or {@code null}. */
    public String cohortScope() {
        JsonNode d = device();
        return d != null && d.hasNonNull("cohortScope") ? d.get("cohortScope").asText() : null;
    }

    /** Fraction of the cohort sharing this profile, or {@code null} if unknown/absent. */
    public Double cohortPrevalence() {
        JsonNode d = device();
        return d != null && d.hasNonNull("cohortPrevalence") ? d.get("cohortPrevalence").asDouble() : null;
    }

    /**
     * Per-PCR prevalence map (PCR index → fraction). Empty if absent.
     *
     * @return a map; never {@code null}
     */
    public Map<String, Double> cohortPrevalencePerPcr() {
        Map<String, Double> out = new LinkedHashMap<>();
        JsonNode d = device();
        JsonNode m = d == null ? null : d.get("cohortPrevalencePerPcr");
        if (m != null && m.isObject()) {
            m.fields().forEachRemaining(e -> {
                if (e.getValue().isNumber()) {
                    out.put(e.getKey(), e.getValue().asDouble());
                }
            });
        }
        return out;
    }

    /** Number of devices in the cohort sample, or {@code null} if unknown/absent. */
    public Long cohortSampleSize() {
        JsonNode d = device();
        return d != null && d.hasNonNull("cohortSampleSize") ? d.get("cohortSampleSize").asLong() : null;
    }

    /** Whether this is a previously-unseen profile, or {@code null} if not evaluated. */
    public Boolean novelProfile() {
        JsonNode d = device();
        return d != null && d.hasNonNull("novelProfile") ? d.get("novelProfile").asBoolean() : null;
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
