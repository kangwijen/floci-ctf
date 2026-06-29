package io.github.hectorvent.floci.core.common;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Propagates operator AWS credentials from the Floci host environment into child
 * containers. Never injects placeholder credentials.
 */
public final class OperatorCredentialEnv {

    private OperatorCredentialEnv() {
    }

    public static void putIfPresent(Map<String, String> env) {
        putIfPresent(env, "AWS_ACCESS_KEY_ID", System.getenv("AWS_ACCESS_KEY_ID"));
        putIfPresent(env, "AWS_SECRET_ACCESS_KEY", System.getenv("AWS_SECRET_ACCESS_KEY"));
        putIfPresent(env, "AWS_SESSION_TOKEN", System.getenv("AWS_SESSION_TOKEN"));
    }

    public static void addIfPresent(List<String> env) {
        addIfPresent(env, "AWS_ACCESS_KEY_ID", System.getenv("AWS_ACCESS_KEY_ID"));
        addIfPresent(env, "AWS_SECRET_ACCESS_KEY", System.getenv("AWS_SECRET_ACCESS_KEY"));
        addIfPresent(env, "AWS_SESSION_TOKEN", System.getenv("AWS_SESSION_TOKEN"));
    }

    public static Map<String, String> snapshot() {
        Map<String, String> creds = new LinkedHashMap<>();
        putIfPresent(creds);
        return creds;
    }

    static void putIfPresent(Map<String, String> env, String key, String value) {
        if (value != null && !value.isBlank()) {
            env.put(key, value);
        }
    }

    static void addIfPresent(List<String> env, String key, String value) {
        if (value != null && !value.isBlank()) {
            env.add(key + "=" + value);
        }
    }
}
