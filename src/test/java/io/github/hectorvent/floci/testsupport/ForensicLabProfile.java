package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.Map;

/**
 * Forensic lab profile: IAM/SigV4 off, in-memory storage, CloudTrail audit recording,
 * and all forensic services enabled (Config, GuardDuty, Security Hub).
 */
public class ForensicLabProfile implements QuarkusTestProfile {

    public static final String ACCOUNT = "000000000000";
    public static final String REGION = "us-east-1";

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.ofEntries(
                Map.entry("floci.services.iam.enforcement-enabled", "false"),
                Map.entry("floci.services.iam.strict-enforcement-enabled", "false"),
                Map.entry("floci.auth.validate-signatures", "false"),
                Map.entry("floci.storage.mode", "memory"),
                Map.entry("floci.services.cloudtrail.enabled", "true"),
                Map.entry("floci.services.cloudtrail.audit-enabled", "true"),
                Map.entry("floci.services.configservice.enabled", "true"),
                Map.entry("floci.services.guardduty.enabled", "true"),
                Map.entry("floci.services.securityhub.enabled", "true"),
                Map.entry("floci.ctf.hide-internal-endpoints", "false"));
    }
}
