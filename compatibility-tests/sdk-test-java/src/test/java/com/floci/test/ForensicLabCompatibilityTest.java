package com.floci.test;

import org.junit.jupiter.api.*;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.LookupEventsResponse;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end audit exercise probes against a live floci-ctf instance.
 *
 * <p>Requires {@code floci.services.cloudtrail.audit-enabled=true} and an active logging trail.
 * When audit is off (default upstream image), tests skip via {@link Assumptions}.
 *
 * <p>GuardDuty and Security Hub use Floci JSON 1.1 targets (not AWS SDK REST clients).
 */
@DisplayName("Audit exercise compatibility")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ForensicLabCompatibilityTest {

    private static CloudTrailClient cloudTrail;
    private static S3Client s3;
    private static String trailName;
    private static String logBucket;
    private static boolean auditEnabled;

    @BeforeAll
    static void setup() {
        cloudTrail = TestFixtures.cloudTrailClient();
        s3 = TestFixtures.s3Client();
        trailName = TestFixtures.uniqueName("audit-compat-trail");
        logBucket = TestFixtures.uniqueName("audit-compat-logs");
        auditEnabled = TestFixtures.isCloudTrailAuditEnabled();
        Assumptions.assumeTrue(auditEnabled,
                "CloudTrail audit delivery not enabled; set FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true");
    }

    @AfterAll
    static void cleanup() {
        if (cloudTrail != null) {
            try {
                cloudTrail.stopLogging(r -> r.name(trailName));
            } catch (Exception ignored) {
            }
            try {
                cloudTrail.deleteTrail(r -> r.name(trailName));
            } catch (Exception ignored) {
            }
            cloudTrail.close();
        }
        if (s3 != null) {
            s3.close();
        }
    }

    @Test
    @Order(1)
    void provisionTrailAndBucket() {
        s3.createBucket(r -> r.bucket(logBucket));
        cloudTrail.createTrail(r -> r.name(trailName).s3BucketName(logBucket));
        cloudTrail.startLogging(r -> r.name(trailName));
    }

    @Test
    @Order(2)
    void managementApiCallProducesLookupEvents() {
        s3.listBuckets();

        LookupEventsResponse response = cloudTrail.lookupEvents(r -> r
                .maxResults(10)
                .startTime(Instant.now().minusSeconds(300))
                .endTime(Instant.now().plusSeconds(60)));

        assertThat(response.events()).isNotEmpty();
        assertThat(response.events().get(0).eventName()).isNotBlank();
    }

    @Test
    @Order(3)
    void cloudTrailLogObjectsLandInS3() {
        ListObjectsV2Response listed = s3.listObjectsV2(r -> r
                .bucket(logBucket)
                .prefix("AWSLogs/"));
        assertThat(listed.contents()).isNotEmpty();
    }

    @Test
    @Order(4)
    void guardDutyJsonApiAcceptsCreateDetector() throws Exception {
        com.fasterxml.jackson.databind.JsonNode response = TestFixtures.postJson11(
                "GuardDuty_2017-11-28.",
                "CreateDetector",
                "{\"Enable\":true,\"FindingPublishingFrequency\":\"FIFTEEN_MINUTES\"}");
        assertThat(response.path("DetectorId").asText()).isNotBlank();
    }

    @Test
    @Order(5)
    void securityHubJsonApiAcceptsEnableAndImport() throws Exception {
        TestFixtures.postJson11("AWSSecurityHub.", "EnableSecurityHub", "{}");
        com.fasterxml.jackson.databind.JsonNode imported = TestFixtures.postJson11(
                "AWSSecurityHub.",
                "BatchImportFindings",
                """
                {
                  "Findings": [{
                    "SchemaVersion": "2018-10-08",
                    "Id": "audit-compat/finding/1",
                    "ProductArn": "arn:aws:securityhub:us-east-1:000000000000:product/audit-compat",
                    "GeneratorId": "audit-compat-generator",
                    "AwsAccountId": "000000000000",
                    "Types": ["Software and Configuration Checks"],
                    "CreatedAt": "2026-06-12T00:00:00Z",
                    "UpdatedAt": "2026-06-12T00:00:00Z",
                    "Severity": {"Label": "MEDIUM"},
                    "Title": "Imported finding sample",
                    "Description": "Imported by ForensicLabCompatibilityTest"
                  }]
                }
                """);
        assertThat(imported.path("SuccessCount").asInt()).isEqualTo(1);
    }
}
