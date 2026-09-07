package io.rootherald;

/**
 * The verify leg named a policy looser than the one the challenge was issued
 * with (HTTP 422, code {@code policy_downgrade}). A challenge fixes the ask
 * when it is minted; verify may only tighten it.
 */
public class PolicyDowngradeException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public static final String ERROR_CODE = "policy_downgrade";

    public PolicyDowngradeException(String message) {
        super(422, ERROR_CODE, message);
    }
}
