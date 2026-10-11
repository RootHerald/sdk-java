package io.rootherald;

/**
 * The challenge asked for something a challenge cannot ask for (HTTP 400,
 * code {@code invalid_ask}), such as the retired {@code "key"} ask, or the
 * key challenge named a purpose the server does not know (code
 * {@code invalid_purpose}). The backend's code is wrong, not the device:
 * keys are minted with {@code issueKeyChallenge} / {@code certifyKey}.
 */
public class InvalidAskException extends RootHeraldApiException {
    private static final long serialVersionUID = 1L;

    public static final String ERROR_CODE = "invalid_ask";
    public static final String PURPOSE_ERROR_CODE = "invalid_purpose";

    public InvalidAskException(String message) {
        this(ERROR_CODE, message);
    }

    public InvalidAskException(String errorCode, String message) {
        super(400, errorCode, message);
    }
}
