package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Mirrors {@code docker-compose.yml} CTF security: IAM + strict + SigV4 + hide-internal.
 */
public class CtfComposeParityProfile implements QuarkusTestProfile {

    public static final String ROOT_ACCESS_KEY_ID = "AKIACTFCOMPOSE01";
    public static final String ROOT_SECRET = "emulator-compose-root-secret-32chars!!";

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.services.iam.enforcement-enabled", "true",
                "floci.services.iam.strict-enforcement-enabled", "true",
                "floci.auth.validate-signatures", "true",
                "floci.auth.root-access-key-id", ROOT_ACCESS_KEY_ID,
                "floci.auth.root-secret-access-key", ROOT_SECRET,
                "floci.ctf.hide-internal-endpoints", "true",
                "floci.services.cloudtrail.enabled", "true",
                "floci.services.cloudtrail.audit-enabled", "true");
    }
}
