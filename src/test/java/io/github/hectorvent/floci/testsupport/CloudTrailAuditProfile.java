package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Enables CloudTrail audit recording with immediate S3 delivery for integration tests.
 */
public class CloudTrailAuditProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.services.cloudtrail.enabled", "true",
                "floci.services.cloudtrail.audit-enabled", "true",
                "floci.services.iam.enforcement-enabled", "false",
                "floci.auth.validate-signatures", "false");
    }
}
