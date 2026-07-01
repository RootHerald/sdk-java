package io.rootherald;

/**
 * Thrown when the RootHerald API returns a non-2xx response during a
 * Background-Check (server -&gt; server) call. Subclasses map specific HTTP
 * statuses, mirroring the {@code @rootherald/node} taxonomy:
 *
 * <ul>
 *   <li>401 → {@link InvalidSecretKeyException}</li>
 *   <li>422 → {@link UnknownPolicyException}</li>
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

    public RootHeraldApiException(int statusCode, String message) {
        super(message);
        this.statusCode = statusCode;
    }

    /** The HTTP status code returned by the RootHerald API. */
    public int statusCode() {
        return statusCode;
    }
}
