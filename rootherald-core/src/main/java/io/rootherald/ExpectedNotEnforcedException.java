package io.rootherald;

/**
 * A verdict did not echo the {@code expectedKey} or {@code expectedDevices}
 * the caller passed to {@code verify}. The API ignores unknown JSON fields,
 * so a server that predates the binding would accept any device and answer a
 * verdict with no {@code expected} block; the SDK refuses that verdict rather
 * than return it. Status 200: the server answered, the binding was not
 * enforced.
 */
public class ExpectedNotEnforcedException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public ExpectedNotEnforcedException(String message) {
        super(200, null, message);
    }
}
