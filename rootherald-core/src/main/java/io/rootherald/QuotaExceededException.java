package io.rootherald;

/**
 * The tenant has exceeded its metered verify quota (HTTP 429 with code
 * {@code quota_exceeded} or an {@code X-RootHerald-Quota} header). A 429
 * without that signal is {@link RateLimitedException}.
 */
public class QuotaExceededException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public QuotaExceededException(String message) {
        this(null, message);
    }

    public QuotaExceededException(String errorCode, String message) {
        super(429, errorCode, message);
    }
}
