package io.rootherald.client;

import java.util.List;

/** Argument checks shared by the option classes. */
final class Aliases {

    private Aliases() {
    }

    /** A non-empty list of non-empty strings, copied; {@code null} stays {@code null}. */
    static List<String> copyOrNull(List<String> values, String field) {
        if (values == null) {
            return null;
        }
        if (values.isEmpty() || values.stream().anyMatch(v -> v == null || v.isEmpty())) {
            throw new IllegalArgumentException(field + " must be a non-empty list of non-empty strings");
        }
        return List.copyOf(values);
    }

    /** A non-empty string; {@code null} stays {@code null}. */
    static String textOrNull(String value, String field) {
        if (value != null && value.isEmpty()) {
            throw new IllegalArgumentException(field + " must be a non-empty string");
        }
        return value;
    }
}
