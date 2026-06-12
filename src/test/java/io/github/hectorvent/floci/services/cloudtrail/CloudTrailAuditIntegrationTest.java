package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testsupport.CloudTrailAuditProfile;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(CloudTrailAuditProfile.class)
class CloudTrailAuditIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String REGION = "us-east-1";
    private static final String S3_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/s3/aws4_request";

    @Inject
    CloudTrailDeliveryService deliveryService;

    @Inject
    CloudTrailEventStore eventStore;

    @Inject
    S3Service s3Service;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @BeforeEach
    void resetStores() {
        eventStore.clear();
        deliveryService.setBufferSizeForTests(1);
    }

    @Test
    void activeTrailRecordsApiCallsToS3AndLookupEvents() {
        String trailBucket = "cloudtrail-audit-target-bucket";
        String auditedBucket = "cloudtrail-audited-bucket";
        String trailName = "api-audit-trail";

        given().when().put("/" + trailBucket).then().statusCode(200);
        given().when().put("/" + auditedBucket).then().statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s",
                            "S3BucketName": "%s",
                            "IncludeGlobalServiceEvents": true,
                            "IsMultiRegionTrail": false
                        }
                        """.formatted(trailName, trailBucket))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s"
                        }
                        """.formatted(trailName))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("Authorization", S3_AUTH)
                .body("audit payload")
        .when()
                .put("/" + auditedBucket + "/audit-object.txt")
        .then()
                .statusCode(200);

        deliveryService.flushAll();

        String prefix = "AWSLogs/000000000000/CloudTrail/" + REGION + "/";
        String objectKey = s3Service.listObjects(trailBucket, prefix, null, 100).stream()
                .map(S3Object::getKey)
                .filter(key -> key.endsWith(".json.gz"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No CloudTrail delivery object under " + prefix));

        byte[] gzipPayload = s3Service.getObject(trailBucket, objectKey).getData();
        String json = readCloudTrailPayload(gzipPayload);
        assertTrue(json.contains("PutObject"));
        assertTrue(json.contains("s3.amazonaws.com"));
        assertTrue(json.contains("eventVersion"));
        assertTrue(json.contains("1.08"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "EventName",
                                    "AttributeValue": "PutObject"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo("PutObject"))
                .body("Events[0].EventSource", equalTo("s3.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("PutObject"))
                .body("Events[0].EventTime", notNullValue());
    }

    @Test
    void noEventsRecordedWhenTrailIsNotLogging() {
        String trailBucket = "cloudtrail-idle-bucket";
        String auditedBucket = "cloudtrail-idle-audited";
        String trailName = "idle-trail";

        given().when().put("/" + trailBucket).then().statusCode(200);
        given().when().put("/" + auditedBucket).then().statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s",
                            "S3BucketName": "%s"
                        }
                        """.formatted(trailName, trailBucket))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("Authorization", S3_AUTH)
                .body("idle")
        .when()
                .put("/" + auditedBucket + "/idle.txt")
        .then()
                .statusCode(200);

        deliveryService.flushAll();

        given()
                .header("Authorization", S3_AUTH)
        .when()
                .get("/" + trailBucket + "?list-type=2&prefix=AWSLogs/")
        .then()
                .statusCode(200)
                .body("ListBucketResult.Contents.size()", equalTo(0));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events.size()", equalTo(0));
    }

    private static String readCloudTrailPayload(byte[] payload) {
        if (payload.length >= 2 && (payload[0] & 0xFF) == 0x1F && (payload[1] & 0xFF) == 0x8B) {
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
