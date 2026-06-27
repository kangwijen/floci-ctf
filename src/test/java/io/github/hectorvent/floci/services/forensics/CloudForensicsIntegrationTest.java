package io.github.hectorvent.floci.services.forensics;

import io.github.hectorvent.floci.services.cloudtrail.CloudTrailDeliveryService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.github.hectorvent.floci.testsupport.ForensicLabProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.zip.GZIPInputStream;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end forensic lab: CloudTrail audit and S3 delivery, S3 access logging,
 * GuardDuty detector findings, Security Hub import, and AWS Config snapshot delivery.
 */
@QuarkusTest
@TestProfile(ForensicLabProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CloudForensicsIntegrationTest {

    private static final String LOG_BUCKET = "ctf-forensic-cloudtrail-logs";
    private static final String WORKLOAD_BUCKET = "ctf-forensic-workload";
    private static final String ACCESS_LOG_BUCKET = "ctf-forensic-access-logs";
    private static final String CONFIG_BUCKET = "ctf-forensic-config-delivery";
    private static final String TRAIL_NAME = "ctf-forensic-audit-trail";
    private static final String FORENSIC_USER = "ctf-forensic-audit-user";
    private static final String ACCESS_LOG_PREFIX = "s3-access/";
    private static final String SECURITY_HUB_PRODUCT_ARN =
            "arn:aws:securityhub:us-east-1:000000000000:product/000000000000/default";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    CloudTrailDeliveryService cloudTrailDeliveryService;

    @Inject
    S3Service s3Service;

    private String guardDutyDetectorId;

    @BeforeAll
    void bindHttp() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        cloudTrailDeliveryService.setBufferSizeForTests(1);
    }

    @Test
    @Order(1)
    void createS3BucketForCloudTrailLogs() {
        CtfLabIamTestSupport.createBucket(LOG_BUCKET);
        CtfLabIamTestSupport.putBucketPolicy(
                LOG_BUCKET,
                CtfLabIamTestSupport.cloudTrailBucketPolicy(
                        LOG_BUCKET, TRAIL_NAME, ForensicLabProfile.ACCOUNT, ForensicLabProfile.REGION));
    }

    @Test
    @Order(2)
    void createCloudTrailTrailAndStartLogging() {
        CtfLabIamTestSupport.cloudTrail("CreateTrail", """
                {
                    "Name": "%s",
                    "S3BucketName": "%s",
                    "IncludeGlobalServiceEvents": true,
                    "IsMultiRegionTrail": false,
                    "IsOrganizationTrail": false
                }
                """.formatted(TRAIL_NAME, LOG_BUCKET))
                .statusCode(200)
                .body("Name", equalTo(TRAIL_NAME))
                .body("TrailARN", startsWith("arn:aws:cloudtrail:"));

        CtfLabIamTestSupport.cloudTrail("StartLogging", """
                {"Name": "%s"}
                """.formatted(TRAIL_NAME))
                .statusCode(200);

        CtfLabIamTestSupport.cloudTrail("GetTrailStatus", """
                {"Name": "%s"}
                """.formatted(TRAIL_NAME))
                .statusCode(200)
                .body("IsLogging", equalTo(true));
    }

    @Test
    @Order(3)
    void performS3PutObjectAndIamListUsers() {
        CtfLabIamTestSupport.createBucket(WORKLOAD_BUCKET);
        CtfLabIamTestSupport.putObject(WORKLOAD_BUCKET, "evidence/artifact.txt", "forensic-payload");
        CtfLabIamTestSupport.createIamUser(FORENSIC_USER);
        CtfLabIamTestSupport.iamQuery("ListUsers")
                .statusCode(200)
                .body(containsString(FORENSIC_USER));
    }

    @Test
    @Order(4)
    void cloudTrailEventsAppearInS3AndLookupEvents() {
        cloudTrailDeliveryService.flushAll();

        String prefix = "AWSLogs/" + ForensicLabProfile.ACCOUNT + "/CloudTrail/" + ForensicLabProfile.REGION + "/";
        List<String> keys = CtfLabIamTestSupport.listBucket(LOG_BUCKET + "?list-type=2&prefix=" + prefix)
                .statusCode(200)
                .body("ListBucketResult.Contents.size()", greaterThan(0))
                .extract().xmlPath()
                .getList("ListBucketResult.Contents.Key", String.class);
        StringBuilder combined = new StringBuilder();
        for (String key : keys) {
            if (!key.endsWith(".json.gz")) {
                continue;
            }
            combined.append(decodeCloudTrailPayload(s3Service.getObject(LOG_BUCKET, key).getData()));
        }
        String json = combined.toString();
        assertFalse(json.isBlank(), "expected CloudTrail log objects under AWSLogs/");
        assertTrue(json.contains("eventVersion"));

        CtfLabIamTestSupport.cloudTrail("LookupEvents", "{}")
                .statusCode(200)
                .body("Events", hasSize(greaterThan(0)))
                .body("Events[0].EventName", notNullValue())
                .body("Events[0].EventSource", notNullValue());
    }

    @Test
    @Order(5)
    void s3AccessLoggingCapturesObjectGet() {
        CtfLabIamTestSupport.createBucket(ACCESS_LOG_BUCKET);
        CtfLabIamTestSupport.createBucket(WORKLOAD_BUCKET);

        String loggingXml = """
                <BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <LoggingEnabled>
                        <TargetBucket>%s</TargetBucket>
                        <TargetPrefix>%s</TargetPrefix>
                    </LoggingEnabled>
                </BucketLoggingStatus>
                """.formatted(ACCESS_LOG_BUCKET, ACCESS_LOG_PREFIX);

        io.restassured.RestAssured.given()
                .queryParam("logging", "")
                .contentType("application/xml")
                .body(loggingXml)
        .when()
                .put("/" + WORKLOAD_BUCKET)
        .then()
                .statusCode(200);

        CtfLabIamTestSupport.putObject(WORKLOAD_BUCKET, "read-me.txt", "payload");
        CtfLabIamTestSupport.getObject(WORKLOAD_BUCKET, "read-me.txt");

        String logKey = CtfLabIamTestSupport.listBucket(ACCESS_LOG_BUCKET + "?prefix=" + ACCESS_LOG_PREFIX)
                .statusCode(200)
                .extract().xmlPath()
                .getString("ListBucketResult.Contents[0].Key");

        String logBody = CtfLabIamTestSupport.getObject(ACCESS_LOG_BUCKET, logKey);
        assertTrue(logBody.contains(WORKLOAD_BUCKET));
        assertTrue(logBody.contains("REST.GET.OBJECT"));
        assertTrue(logBody.contains("read-me.txt"));
    }

    @Test
    @Order(6)
    void guardDutyDetectorAndSecurityHubFindingImport() {
        guardDutyDetectorId = CtfLabIamTestSupport.guardDuty("CreateDetector", """
                {
                    "enable": true,
                    "findingPublishingFrequency": "ONE_HOUR"
                }
                """)
                .statusCode(200)
                .extract().jsonPath().getString("detectorId");

        CtfLabIamTestSupport.guardDuty("CreateSampleFindings", """
                {
                    "DetectorId": "%s",
                    "FindingTypes": ["Policy:IAMUser/RootCredentialUsage"]
                }
                """.formatted(guardDutyDetectorId))
                .statusCode(200);

        CtfLabIamTestSupport.guardDuty("ListFindings", """
                {"DetectorId": "%s", "FindingCriteria": {}}
                """.formatted(guardDutyDetectorId))
                .statusCode(200)
                .body("findingIds", hasSize(greaterThan(0)));

        CtfLabIamTestSupport.securityHub("EnableSecurityHub", "{}")
                .statusCode(200);

        CtfLabIamTestSupport.securityHub("BatchImportFindings", """
                {
                    "Findings": [
                        {
                            "SchemaVersion": "2018-10-08",
                            "Id": "ctf-forensic-imported-finding",
                            "ProductArn": "%s",
                            "GeneratorId": "ctf-forensic-lab",
                            "AwsAccountId": "%s",
                            "Region": "%s",
                            "Title": "Forensic lab imported finding",
                            "Description": "Imported during CloudForensicsIntegrationTest",
                            "Severity": {"Label": "MEDIUM", "Normalized": 50},
                            "Compliance": {"Status": "FAILED"},
                            "Workflow": {"Status": "NEW"}
                        }
                    ]
                }
                """.formatted(SECURITY_HUB_PRODUCT_ARN, ForensicLabProfile.ACCOUNT, ForensicLabProfile.REGION))
                .statusCode(200)
                .body("SuccessCount", equalTo(1))
                .body("FailedCount", equalTo(0));

        CtfLabIamTestSupport.securityHub("GetFindings", """
                {"Filters": {"Id": [{"Value": "ctf-forensic-imported-finding", "Comparison": "EQUALS"}]}}
                """)
                .statusCode(200)
                .body("Findings", hasSize(1))
                .body("Findings[0].Title", equalTo("Forensic lab imported finding"));
    }

    @Test
    @Order(7)
    void configRecorderDeliversSnapshotToS3() throws Exception {
        CtfLabIamTestSupport.createBucket(CONFIG_BUCKET);

        CtfLabIamTestSupport.configService("PutConfigurationRecorder", """
                {
                    "ConfigurationRecorder": {
                        "name": "default",
                        "roleARN": "arn:aws:iam::%s:role/config-role",
                        "recordingGroup": {
                            "allSupported": true,
                            "includeGlobalResourceTypes": true
                        }
                    }
                }
                """.formatted(ForensicLabProfile.ACCOUNT))
                .statusCode(200);

        CtfLabIamTestSupport.configService("PutDeliveryChannel", """
                {
                    "DeliveryChannel": {
                        "name": "default",
                        "s3BucketName": "%s",
                        "s3KeyPrefix": "config-snapshots"
                    }
                }
                """.formatted(CONFIG_BUCKET))
                .statusCode(200);

        CtfLabIamTestSupport.configService("StartConfigurationRecorder", """
                {"ConfigurationRecorderName": "default"}
                """)
                .statusCode(200);

        List<S3Object> objects = s3Service.listObjects(CONFIG_BUCKET, "config-snapshots/AWSLogs/", null, 100);
        assertFalse(objects.isEmpty(), "expected Config snapshot object in delivery bucket");
        S3Object snapshotObject = objects.stream()
                .filter(o -> o.getKey().contains("ConfigSnapshot-") && o.getKey().endsWith(".json"))
                .findFirst()
                .orElseThrow();
        assertTrue(snapshotObject.getKey().startsWith("config-snapshots/AWSLogs/"));
        S3Object stored = s3Service.getObject(CONFIG_BUCKET, snapshotObject.getKey());
        String snapshotJson = new String(stored.getData(), StandardCharsets.UTF_8);
        assertTrue(snapshotJson.contains("configurationItems"));
    }

    private static String decodeCloudTrailPayload(byte[] payload) {
        if (payload.length >= 2 && payload[0] == (byte) 0x1f && payload[1] == (byte) 0x8b) {
            try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(payload));
                 ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                gzip.transferTo(out);
                return out.toString(StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new AssertionError("Failed to gunzip CloudTrail payload", e);
            }
        }
        return new String(payload, StandardCharsets.UTF_8);
    }
}
