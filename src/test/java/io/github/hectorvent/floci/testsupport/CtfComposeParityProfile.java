package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Mirrors {@code docker-compose.yml} CTF security via Quarkus profile {@code ctf}
 * ({@code application-ctf.yml}: IAM + strict + SigV4 + federated + egress) plus operator root
 * and audit knobs that Compose sets separately.
 */
public class CtfComposeParityProfile implements QuarkusTestProfile {

    public static final String ROOT_ACCESS_KEY_ID = "AKIACTFCOMPOSE01";
    public static final String ROOT_SECRET = "emulator-compose-root-secret-32chars!!";

    @Override
    public String getConfigProfile() {
        return "ctf";
    }

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.auth.root-access-key-id", ROOT_ACCESS_KEY_ID,
                "floci.auth.root-secret-access-key", ROOT_SECRET,
                "floci.ctf.hide-internal-endpoints", "true",
                "floci.services.cloudtrail.enabled", "true",
                "floci.services.cloudtrail.audit-enabled", "true");
    }
}
