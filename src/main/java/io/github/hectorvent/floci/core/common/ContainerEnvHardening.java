package io.github.hectorvent.floci.core.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Prevents user-controlled container environment (Lambda config, ECS task defs/overrides,
 * CodeBuild project env) from injecting AWS or Floci operator credentials. Only
 * {@link OperatorCredentialEnv} may supply those keys on the host.
 */
public final class ContainerEnvHardening {

    private static final Set<String> BLOCKED_KEYS = Set.of(
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "AWS_SESSION_TOKEN",
            "AWS_SECURITY_TOKEN",
            "FLOCI_AUTH_ROOT_ACCESS_KEY_ID",
            "FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY",
            "FLOCI_AUTH_PRESIGN_SECRET");

    private ContainerEnvHardening() {
    }

    public static boolean isBlocked(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String upper = key.toUpperCase(Locale.ROOT);
        if (BLOCKED_KEYS.contains(upper)) {
            return true;
        }
        return upper.startsWith("FLOCI_AUTH_");
    }

    public static void removeBlockedKeys(Map<String, String> env) {
        if (env == null || env.isEmpty()) {
            return;
        }
        env.keySet().removeIf(ContainerEnvHardening::isBlocked);
    }

    public static void putIfAllowed(Map<String, String> env, String key, String value) {
        if (!isBlocked(key)) {
            env.put(key, value);
        }
    }

    public static void putAllIfAllowed(Map<String, String> env, Map<String, String> additions) {
        if (additions == null) {
            return;
        }
        additions.forEach((k, v) -> putIfAllowed(env, k, v));
    }

    public static List<String> filterEnvList(List<String> envVars) {
        if (envVars == null || envVars.isEmpty()) {
            return List.of();
        }
        List<String> filtered = new ArrayList<>(envVars.size());
        for (String entry : envVars) {
            if (entry == null) {
                continue;
            }
            int eq = entry.indexOf('=');
            String key = eq >= 0 ? entry.substring(0, eq) : entry;
            if (!isBlocked(key)) {
                filtered.add(entry);
            }
        }
        return filtered;
    }

    /**
     * Merges user-supplied entries into {@code target}, strips blocked keys, then applies
     * {@link OperatorCredentialEnv} so host operator credentials cannot be overridden.
     */
    public static void mergeUserEnvThenOperatorCredentials(Map<String, String> target,
                                                           Map<String, String> userSupplied) {
        putAllIfAllowed(target, userSupplied);
        removeBlockedKeys(target);
        OperatorCredentialEnv.putIfPresent(target);
    }

    public static Map<String, String> mergeUserEnvListToMap(
            Map<String, String> taskDefEnv,
            Map<String, String> overrideEnv) {
        Map<String, String> merged = new LinkedHashMap<>();
        putAllIfAllowed(merged, taskDefEnv);
        putAllIfAllowed(merged, overrideEnv);
        removeBlockedKeys(merged);
        return merged;
    }
}
