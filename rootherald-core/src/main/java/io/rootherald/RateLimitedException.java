package io.rootherald;

/**
 * The request-rate limiter refused the call (HTTP 429 without a quota signal).
 * Retry after {@link #retryAfterSeconds()}. Distinct from
 * {@link QuotaExceededException}, the metered billing ceiling.
 */
public class RateLimitedException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    private final Integer retryAfterSeconds;

    /**
     * @param errorCode         the server's {@code error} code, or {@code null}
     * @param message           human-readable detail
     * @param retryAfterSeconds seconds to wait before retrying: the
     *                          {@code Retry-After} header, else the body's
     *                          {@code retryAfterSeconds}, else {@code null}
     */
    public RateLimitedException(String errorCode, String message, Integer retryAfterSeconds) {
        super(429, errorCode, message);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    /** Seconds to wait before retrying, or {@code null} when the server gave none. */
    public Integer retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
