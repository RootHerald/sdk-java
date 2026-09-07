package io.rootherald;

/**
 * Thrown when the RootHerald API returns a non-2xx response during a
 * Background-Check (server -&gt; server) call. Subclasses map specific HTTP
 * statuses, mirroring the {@code @rootherald/node} taxonomy:
 *
 * <ul>
 *   <li>401 → {@link InvalidSecretKeyException}</li>
 *   <li>422 → {@link UnknownPolicyException}, or by server code
 *       {@link PolicyDowngradeException} ({@code policy_downgrade}) /
 *       {@link AdmissionRefusedException} ({@code admission_refused})</li>
 *   <li>409 → {@link ChallengeException}</li>
 *   <li>400 → {@link InvalidEvidenceException}</li>
 *   <li>429 → {@link QuotaExceededException}</li>
 * </ul>
 *
 * Note: an un-enrolled / failing device is NOT an error — it returns a normal
 * verdict. Only protocol/auth/quota problems raise one of these.
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
     *                   {@code unknown_policy}, {@code policy_downgrade}), or
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
