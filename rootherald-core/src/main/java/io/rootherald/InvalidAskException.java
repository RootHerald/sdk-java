package io.rootherald;

/**
 * The challenge asked for something a challenge cannot ask for (HTTP 400,
 * code {@code invalid_ask}), such as the retired {@code "key"} ask. The
 * backend's code is wrong, not the device: keys are minted with
 * {@code issueKeyChallenge} / {@code certifyKey}.
 */
public class InvalidAskException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public static final String ERROR_CODE = "invalid_ask";

    public InvalidAskException(String message) {
        super(400, ERROR_CODE, message);
    }
}
