package io.rootherald;

/**
 * The API key's budget cannot pay for a device new to the period (HTTP 429
 * with code {@code budget_exhausted} or an {@code X-RootHerald-Quota}
 * header). {@link #budget()} names the budget that refused, when the server
 * did. A 429 without that signal is {@link RateLimitedException}.
 */
public class QuotaExceededException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public static final String ERROR_CODE = "budget_exhausted";

    private final RefusingBudget budget;

    public QuotaExceededException(String errorCode, String message) {
        this(errorCode, message, null);
    }

    /**
     * @param errorCode the server's {@code error} code, or {@code null}
     * @param message   human-readable detail
     * @param budget    the budget that refused, or {@code null} when the server named none
     */
    public QuotaExceededException(String errorCode, String message, RefusingBudget budget) {
        super(429, errorCode, message);
        this.budget = budget;
    }

    /** The budget that refused, or {@code null} when the server named none. */
    public RefusingBudget budget() {
        return budget;
    }
}
