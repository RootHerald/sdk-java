package io.rootherald;

/** The account's attestation quota or rate limit was exceeded (HTTP 429). */
public class QuotaExceededException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public QuotaExceededException(String message) {
        super(429, message);
    }
}
