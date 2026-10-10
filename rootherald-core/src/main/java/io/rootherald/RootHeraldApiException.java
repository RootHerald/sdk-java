package io.rootherald;

/**
 * Thrown when the RootHerald API returns a non-2xx response during a
 * Background-Check (server -&gt; server) call. Subclasses map specific HTTP
 * statuses, mirroring the {@code @rootherald/node} taxonomy:
 *
 * <ul>
 *   <li>401 {@code activation_refused} → {@link ActivationRefusedException};
 *       any other 401 → {@link InvalidSecretKeyException}</li>
 *   <li>422 {@code unknown_policy} (or no code) → {@link UnknownPolicyException};
 *       422 {@code admission_refused} → {@link AdmissionRefusedException}</li>
 *   <li>409 → {@link ChallengeException}, except {@code key_rotation_conflict}</li>
 *   <li>400 {@code invalid_ask} or {@code invalid_purpose} → {@link InvalidAskException};
 *       any other 400, including {@code invalid_certification} → {@link InvalidEvidenceException}</li>
 *   <li>429 {@code budget_exhausted}, or an {@code X-RootHerald-Quota} header →
 *       {@link QuotaExceededException}; any other 429 →
 *       {@link RateLimitedException}</li>
 * </ul>
 *
 * Where one status carries two refusals the server's error code
 * ({@link #errorCode()}) or a header tells them apart. A status or code no
 * subclass covers — 422 {@code expected_unknown}, {@code key_disclosure_too_low},
 * {@code purpose_unsupported}, {@code certification_rejected} and
 * {@code posture_not_bound}, 409 {@code key_rotation_conflict}, 402
 * {@code plan_lapsed} — is this base type with the code preserved.
 * <p>
 * A 200 whose body the SDK refuses is one too: a verdict token outside
 * pass/warn/fail, a malformed certified key, or a verdict that does not echo
 * the binding the caller named ({@link ExpectedNotEnforcedException}).
 * <p>
 * Note: an un-enrolled / failing device is NOT an error — it returns a normal
 * verdict. Only protocol/auth/budget problems raise one of these.
 */
public class RootHeraldApiException extends RootHeraldException {
    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final String errorCode;

    public RootHeraldApiException(int statusCode, String message) {
        this(statusCode, null, message);
    }

    /**
     * @param statusCode the HTTP status
     * @param errorCode  the server's {@code error} discriminator (e.g.
     *                   {@code unknown_policy}, {@code admission_refused}), or
     *                   {@code null} when the body carried none
     * @param message    human-readable detail
     */
    public RootHeraldApiException(int statusCode, String errorCode, String message) {
        super(message);
        this.statusCode = statusCode;
        this.errorCode = errorCode;
    }

    /** The HTTP status code returned by the RootHerald API. */
    public int statusCode() {
        return statusCode;
    }

    /**
     * The machine-readable {@code error} code from the response body, or
     * {@code null} when the server did not send one. Match on this to tell
     * the 422 variants apart when catching the base type.
     */
    public String errorCode() {
        return errorCode;
    }
}
