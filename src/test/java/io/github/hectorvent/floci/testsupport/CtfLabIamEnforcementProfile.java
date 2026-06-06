package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Enables CTF IAM enforcement and strict mode for lab-capability integration tests.
 * SigV4 validation is off so tests can use a static Authorization header shape.
 */
public class CtfLabIamEnforcementProfile implements QuarkusTestProfile {

    public static final String ROOT_ACCESS_KEY_ID = "AKIACTFLABROOT01";
    public static final String ROOT_SECRET = "ctf-lab-root-secret-32chars!!!!";
    public static final String ACCOUNT = "000000000000";
    public static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=" + ROOT_ACCESS_KEY_ID + "/20260227/us-east-1/iam/aws4_request";

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.services.iam.enforcement-enabled", "true",
                "floci.services.iam.strict-enforcement-enabled", "true",
                "floci.auth.validate-signatures", "false",
                "floci.auth.root-access-key-id", ROOT_ACCESS_KEY_ID,
                "floci.auth.root-secret-access-key", ROOT_SECRET);
    }
}
