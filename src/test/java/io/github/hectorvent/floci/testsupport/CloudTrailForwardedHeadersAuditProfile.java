package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * CloudTrail audit recording with trusted {@code X-Forwarded-For} for synthetic {@code sourceIPAddress}.
 */
public class CloudTrailForwardedHeadersAuditProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "floci.services.cloudtrail.enabled", "true",
                "floci.services.cloudtrail.audit-enabled", "true",
                "floci.services.iam.enforcement-enabled", "false",
                "floci.auth.validate-signatures", "false",
                "floci.auth.trust-forwarded-headers", "true");
    }
}
