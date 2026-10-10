package io.rootherald.client;

import java.util.List;

/**
 * What the challenge bound the verdict to, echoed by the server after it
 * enforced it ({@code verdict.expected}). Absent when the challenge named
 * nothing.
 *
 * @param key     the {@code expectedKey} the challenge named, or {@code null}
 * @param devices the {@code expectedDevices} the challenge named, or {@code null}
 */
public record ExpectedBinding(String key, List<String> devices) {

    public ExpectedBinding {
        devices = devices == null ? null : List.copyOf(devices);
    }
}
