package io.rootherald;

/** The named policy is unknown or not owned by this tenant (HTTP 422). */
public class UnknownPolicyException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public UnknownPolicyException(String message) {
        super(422, message);
    }
}
