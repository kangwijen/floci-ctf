package io.github.hectorvent.floci.fuzz.oracle;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Security-first oracle helpers. Failures are recorded and rethrown as {@link AssertionError}
 * so jqwik/JUnit treat them as property failures.
 */
public final class SecurityOracle {

    private SecurityOracle() {
    }

    public static void expectDeny(boolean allowed, String target, String seed, String reason) {
        if (allowed) {
            failSecurity(target, seed, "unexpected Allow: " + reason, Map.of("decision", "ALLOW"));
        }
    }

    public static void expectAllow(boolean allowed, String target, String seed, String reason) {
        if (!allowed) {
            failSecurity(target, seed, "unexpected Deny: " + reason, Map.of("decision", "DENY"));
        }
    }

    public static void expectNoAuthBypass(boolean bypassed, String target, String seed, String reason) {
        if (bypassed) {
            failSecurity(target, seed, "auth bypass: " + reason, Map.of());
        }
    }

    public static void expectArnNotUnderScoped(String actualArn, String forbiddenPrefix,
                                               String target, String seed) {
        if (actualArn != null && actualArn.startsWith(forbiddenPrefix)) {
            Map<String, String> details = new LinkedHashMap<>();
            details.put("arn", actualArn);
            details.put("forbiddenPrefix", forbiddenPrefix);
            failSecurity(target, seed, "ARN under-scoped to forbidden prefix", details);
        }
    }

    public static void expectNoCredentialKey(Map<String, String> env, String target, String seed) {
        for (String key : env.keySet()) {
            String upper = key.toUpperCase();
            if (upper.contains("AWS_ACCESS_KEY")
                    || upper.contains("AWS_SECRET")
                    || upper.contains("AWS_SESSION_TOKEN")
                    || "AWS_SECURITY_TOKEN".equals(upper)) {
                Map<String, String> details = new LinkedHashMap<>();
                details.put("key", key);
                failSecurity(target, seed, "blocked credential key retained in container env", details);
            }
        }
    }

    public static void failSecurity(String target, String seed, String summary,
                                    Map<String, String> details) {
        Finding finding = new Finding(Finding.Kind.SECURITY, target, summary, seed, details);
        try {
            FindingSerializer.write(finding);
        } catch (Exception ignored) {
            // Still fail the property even if disk write fails.
        }
        throw new AssertionError("[" + target + "] " + summary + " seed=" + truncate(seed));
    }

    public static void recordCrash(String target, String seed, Throwable t) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put("exception", t.getClass().getName());
        details.put("message", String.valueOf(t.getMessage()));
        Finding finding = new Finding(Finding.Kind.CRASH, target, "uncaught throwable", seed, details);
        try {
            FindingSerializer.write(finding);
        } catch (Exception ignored) {
            // ignore
        }
    }

    public static <T> T runCatching(String target, String seed, Supplier<T> action) {
        try {
            return action.get();
        } catch (AssertionError ae) {
            throw ae;
        } catch (Throwable t) {
            if (t instanceof OutOfMemoryError || t instanceof StackOverflowError) {
                recordCrash(target, seed, t);
                throw t;
            }
            // Expected parser rejections are fine; only Error subclasses and unexpected Errors matter.
            if (t instanceof Error) {
                recordCrash(target, seed, t);
                throw (Error) t;
            }
            return null;
        }
    }

    public static void runCatchingVoid(String target, String seed, Runnable action) {
        runCatching(target, seed, () -> {
            action.run();
            return Boolean.TRUE;
        });
    }

    private static String truncate(String seed) {
        if (seed == null) {
            return "";
        }
        return seed.length() <= 200 ? seed : seed.substring(0, 200) + "...";
    }
}
