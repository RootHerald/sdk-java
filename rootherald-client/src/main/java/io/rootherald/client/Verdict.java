package io.rootherald.client;

/**
 * The verdict values the server emits at {@code verdict.device.verdict}, as
 * {@link AttestResult#verdict()} returns them. The same vocabulary in every
 * RootHerald SDK; a response carrying any other token is refused.
 */
public final class Verdict {

    /** The device satisfied the policy. */
    public static final String PASS = "pass";
    /** The device passed with reduced assurance; the policy says whether to proceed. */
    public static final String WARN = "warn";
    /** The device did not satisfy the policy, or is not enrolled (see {@link AttestResult#enrollmentRequired()}). */
    public static final String FAIL = "fail";

    private Verdict() {
    }

    /** The token when it is one of the three, else {@code null}. */
    static String parse(String raw) {
        if (raw == null) {
            return null;
        }
        return switch (raw.trim().toLowerCase()) {
            case PASS -> PASS;
            case WARN -> WARN;
            case FAIL -> FAIL;
            default -> null;
        };
    }
}
