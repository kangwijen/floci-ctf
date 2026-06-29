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
        assertTrue(ContainerEnvHardening.isBlocked("floci_auth_custom"));
        assertFalse(ContainerEnvHardening.isBlocked("CHALLENGE_FLAG"));
    }

    @Test
    void blocksCredentialBypassEnvKeys() {
        assertTrue(ContainerEnvHardening.isBlocked("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
        assertTrue(ContainerEnvHardening.isBlocked("AWS_EC2_METADATA_SERVICE_ENDPOINT"));
        assertTrue(ContainerEnvHardening.isBlocked("ECS_CONTAINER_METADATA_URI_V4"));
        assertTrue(ContainerEnvHardening.isBlocked("AWS_SHARED_CREDENTIALS_FILE"));
    }

    @Test
    void operatorCredentialsWinAfterUserEnv() {
        Map<String, String> env = new LinkedHashMap<>();
        env.put("AWS_ACCESS_KEY_ID", "player-key");
        env.put("PLAYER_ROLE", "scanner");

        ContainerEnvHardening.mergeUserEnvThenOperatorCredentials(env, Map.of(
                "AWS_SECRET_ACCESS_KEY", "player-secret"));

        assertEquals("scanner", env.get("PLAYER_ROLE"));
        assertFalse("player-secret".equals(env.get("AWS_SECRET_ACCESS_KEY")),
                "user-supplied secret must not survive merge");
        assertFalse("player-key".equals(env.get("AWS_ACCESS_KEY_ID")),
                "user-supplied access key must not survive merge");
    }

    @Test
    void userEnvCannotInjectContainerCredentialsUri() {
        Map<String, String> env = new LinkedHashMap<>();
        ContainerEnvHardening.putAllIfAllowed(env, Map.of(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://attacker/creds",
                "PLAYER_VAR", "ok"));
        assertFalse(env.containsKey("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
        assertEquals("ok", env.get("PLAYER_VAR"));
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
