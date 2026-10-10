package io.rootherald.client;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The result of {@link RootHeraldClient#verify(String, AttestOptions)}:
 * the device verdict and the full verdict node.
 * <p>
 * {@code assuranceClaimsMet} and {@code enrollmentRequired} are top-level
 * siblings of {@code verdict} on the wire (NOT nested inside it), mirroring
 * {@code @rootherald/node}. Customers gate capabilities on
 * {@code assuranceClaimsMet} and drive the enroll-on-miss flow on
 * {@code enrollmentRequired}. Attestation releases no key; keys come from
 * {@link RootHeraldClient#certifyKey(String, String)}.
 *
 * @param verdict            the server's verdict token, {@link Verdict#PASS}, {@link Verdict#WARN}
 *                           or {@link Verdict#FAIL}; a response carrying any other token is refused
 * @param verdictNode        the full verdict object returned by the server; every device field
 *                           the server sends is under {@code device}
 * @param assuranceClaimsMet assurance-claim URNs the device satisfied; empty if absent, never {@code null}
 * @param enrollmentRequired {@code true} when the quote did not resolve to a live installation of
 *                           yours; the client should enroll, and the verdict is not to be trusted
 */
public record AttestResult(String verdict, JsonNode verdictNode,
                           List<String> assuranceClaimsMet, boolean enrollmentRequired) {

    public AttestResult {
        assuranceClaimsMet = assuranceClaimsMet == null
                ? List.of() : List.copyOf(assuranceClaimsMet);
    }

    /** True when the verdict is {@link Verdict#PASS}. */
    public boolean isPass() {
        return Verdict.PASS.equals(verdict);
    }

    /**
     * This tenant's alias for the device ({@code verdict.device.ueid}), the
     * same id {@link RelayActivateResponse#deviceId()} returned at
     * enrollment. Empty when the disclosure class withholds it.
     */
    public Optional<String> deviceId() {
        JsonNode d = device();
        if (d == null || !d.hasNonNull("ueid") || !d.get("ueid").isTextual()) {
            return Optional.empty();
        }
        String ueid = d.get("ueid").asText();
        return ueid.isBlank() ? Optional.empty() : Optional.of(ueid);
    }

    /**
     * What the challenge bound the verdict to, echoed by the server after it
     * enforced it ({@code verdict.expected}). Empty when the challenge named
     * nothing. {@link RootHeraldClient#verify(String, AttestOptions)} already
     * compared it with the options it was given.
     */
    public Optional<ExpectedBinding> expected() {
        JsonNode e = verdictNode == null ? null : verdictNode.get("expected");
        if (e == null || !e.isObject()) {
            return Optional.empty();
        }
        String key = e.hasNonNull("key") && e.get("key").isTextual() ? e.get("key").asText() : null;
        List<String> devices = null;
        if (e.hasNonNull("devices") && e.get("devices").isArray()) {
            devices = new ArrayList<>();
            for (JsonNode d : e.get("devices")) {
                if (d.isTextual()) {
                    devices.add(d.asText());
                }
            }
        }
        return Optional.of(new ExpectedBinding(key, devices));
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
}
