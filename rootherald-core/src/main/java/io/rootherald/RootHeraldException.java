package io.rootherald;

/**
 * Base exception thrown by any RootHerald SDK component.
 * <p>
 * All other RootHerald exceptions extend this so callers can write a single
 * catch clause for SDK errors when desired.
 */
public class RootHeraldException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public RootHeraldException(String message) {
        super(message);
    }

    public RootHeraldException(String message, Throwable cause) {
        super(message, cause);
    }
}
