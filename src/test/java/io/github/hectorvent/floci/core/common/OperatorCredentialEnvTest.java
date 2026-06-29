package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OperatorCredentialEnvTest {

    @Test
    void putIfPresentSkipsNullAndBlankValues() {
        Map<String, String> env = new LinkedHashMap<>();
        OperatorCredentialEnv.putIfPresent(env, "AWS_ACCESS_KEY_ID", null);
        OperatorCredentialEnv.putIfPresent(env, "AWS_SECRET_ACCESS_KEY", "");
        OperatorCredentialEnv.putIfPresent(env, "AWS_SESSION_TOKEN", "   ");
        assertTrue(env.isEmpty());

        OperatorCredentialEnv.putIfPresent(env, "AWS_ACCESS_KEY_ID", "AKIATEST");
        assertEquals("AKIATEST", env.get("AWS_ACCESS_KEY_ID"));
        assertFalse(env.containsKey("AWS_SECRET_ACCESS_KEY"));
    }

    @Test
    void addIfPresentSkipsNullAndBlankValues() {
        List<String> env = new ArrayList<>();
        OperatorCredentialEnv.addIfPresent(env, "AWS_ACCESS_KEY_ID", null);
        OperatorCredentialEnv.addIfPresent(env, "AWS_SECRET_ACCESS_KEY", "  ");
        assertTrue(env.isEmpty());

        OperatorCredentialEnv.addIfPresent(env, "AWS_SESSION_TOKEN", "token-value");
        assertEquals(List.of("AWS_SESSION_TOKEN=token-value"), env);
    }

    @Test
    void putIfPresentFromEnvLeavesMapUnchangedWhenEnvAbsent() {
        Assumptions.assumeTrue(System.getenv("AWS_ACCESS_KEY_ID") == null);
        Assumptions.assumeTrue(System.getenv("AWS_SECRET_ACCESS_KEY") == null);
        Assumptions.assumeTrue(System.getenv("AWS_SESSION_TOKEN") == null);

        Map<String, String> env = new LinkedHashMap<>();
        env.put("CUSTOM_VAR", "sample");
        OperatorCredentialEnv.putIfPresent(env);
        assertEquals(Map.of("CUSTOM_VAR", "sample"), env);
    }

    @Test
    void addIfPresentFromEnvLeavesListUnchangedWhenEnvAbsent() {
        Assumptions.assumeTrue(System.getenv("AWS_ACCESS_KEY_ID") == null);
        Assumptions.assumeTrue(System.getenv("AWS_SECRET_ACCESS_KEY") == null);
        Assumptions.assumeTrue(System.getenv("AWS_SESSION_TOKEN") == null);

        List<String> env = new ArrayList<>(List.of("PLAYER=ok"));
        OperatorCredentialEnv.addIfPresent(env);
        assertEquals(List.of("PLAYER=ok"), env);
    }

    @Test
    void snapshotEmptyWhenEnvAbsent() {
        Assumptions.assumeTrue(System.getenv("AWS_ACCESS_KEY_ID") == null);
        Assumptions.assumeTrue(System.getenv("AWS_SECRET_ACCESS_KEY") == null);
        Assumptions.assumeTrue(System.getenv("AWS_SESSION_TOKEN") == null);

        assertTrue(OperatorCredentialEnv.snapshot().isEmpty());
    }

    @Test
    void snapshotIncludesOnlyNonBlankEnvValues() {
        Map<String, String> env = new LinkedHashMap<>();
        OperatorCredentialEnv.putIfPresent(env, "AWS_ACCESS_KEY_ID", "AKIATEST");
        OperatorCredentialEnv.putIfPresent(env, "AWS_SECRET_ACCESS_KEY", "secret");
        OperatorCredentialEnv.putIfPresent(env, "AWS_SESSION_TOKEN", "session");

        assertEquals(Map.of(
                "AWS_ACCESS_KEY_ID", "AKIATEST",
                "AWS_SECRET_ACCESS_KEY", "secret",
                "AWS_SESSION_TOKEN", "session"), env);
    }
}
