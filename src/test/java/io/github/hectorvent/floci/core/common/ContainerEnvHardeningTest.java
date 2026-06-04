package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContainerEnvHardeningTest {

    @Test
    void blocksAwsAndFlociAuthKeys() {
        assertTrue(ContainerEnvHardening.isBlocked("AWS_ACCESS_KEY_ID"));
        assertTrue(ContainerEnvHardening.isBlocked("FLOCI_AUTH_PRESIGN_SECRET"));
        assertTrue(ContainerEnvHardening.isBlocked("floci_auth_custom"));
        assertFalse(ContainerEnvHardening.isBlocked("CHALLENGE_FLAG"));
    }

    @Test
    void operatorCredentialsWinAfterUserEnv() {
        Map<String, String> env = new LinkedHashMap<>();
        env.put("AWS_ACCESS_KEY_ID", "player-key");
        env.put("PLAYER_ROLE", "scanner");

        ContainerEnvHardening.mergeUserEnvThenOperatorCredentials(env, Map.of(
                "AWS_SECRET_ACCESS_KEY", "player-secret"));

        assertEquals("scanner", env.get("PLAYER_ROLE"));
        assertFalse(env.containsKey("AWS_SECRET_ACCESS_KEY"));
    }

    @Test
    void filterEnvListDropsBlockedEntries() {
        List<String> filtered = ContainerEnvHardening.filterEnvList(List.of(
                "PLAYER=x",
                "AWS_ACCESS_KEY_ID=test",
                "FLOCI_AUTH_ROOT_ACCESS_KEY_ID=AKIA"));
        assertEquals(List.of("PLAYER=x"), filtered);
    }
}
