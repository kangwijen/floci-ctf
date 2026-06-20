package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * CloudTrail S3 delivery with IAM enforcement: bucket policy requires {@code aws:SourceArn}
 * on {@code s3:PutObject}; in-process delivery must pass the trail ARN.
 */
@QuarkusTest
@TestProfile(CloudTrailS3DeliveryIntegrationTest.Profile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloudTrailS3DeliveryIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = CtfLabIamTestSupport.CLOUDTRAIL_TARGET_PREFIX;
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String LOG_BUCKET = "ctf-cloudtrail-delivery-logs";
    private static final String ACTIVITY_BUCKET = "ctf-cloudtrail-activity";
    private static final String TRAIL_NAME = "ctf-audit-trail";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    CloudTrailDeliveryService deliveryService;

    @Inject
    S3Service s3Service;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        deliveryService.setBufferSizeForTests(1);

        String rootS3 = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3");
        String rootCloudTrail = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "cloudtrail");

        given().header("Authorization", rootS3).when().put("/" + LOG_BUCKET).then().statusCode(200);
        given().header("Authorization", rootS3).when().put("/" + ACTIVITY_BUCKET).then().statusCode(200);

        given()
                .header("Authorization", rootS3)
                .contentType("application/json")
                .body(cloudTrailBucketPolicy(LOG_BUCKET, TRAIL_NAME))
        .when()
                .put("/" + LOG_BUCKET + "?policy")
        .then()
                .statusCode(200);

        given()
                .header("Authorization", rootCloudTrail)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s",
                            "S3BucketName": "%s",
                            "IncludeGlobalServiceEvents": true,
                            "IsMultiRegionTrail": false
                        }
                        """.formatted(TRAIL_NAME, LOG_BUCKET))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("TrailARN", startsWith("arn:aws:cloudtrail:"));

        given()
                .header("Authorization", rootCloudTrail)
                .header("X-Amz-Target", TARGET_PREFIX + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("""
                        {"Name": "%s"}
                        """.formatted(TRAIL_NAME))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    @Test
    void cloudTrailDeliversLogsToS3WhenBucketPolicyRequiresSourceArn() {
        String rootS3 = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3");

        given()
                .header("Authorization", rootS3)
                .contentType("text/plain")
                .body("delivery-test-payload")
        .when()
                .put("/" + ACTIVITY_BUCKET + "/activity-object.txt")
        .then()
                .statusCode(200);

        deliveryService.flushAll();

        String prefix = "AWSLogs/" + ACCOUNT + "/CloudTrail/" + REGION + "/";
        var objects = s3Service.listObjects(LOG_BUCKET, prefix, null, 100);
        assertFalse(objects.isEmpty(), "expected CloudTrail log objects under AWSLogs/");

        String objectKey = objects.stream()
                .map(S3Object::getKey)
                .filter(key -> key.endsWith(".json.gz"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No .json.gz object under " + prefix));

        byte[] payload = s3Service.getObject(LOG_BUCKET, objectKey).getData();
        assertFalse(payload.length == 0, "CloudTrail delivery object should not be empty");

        given()
                .header("Authorization", rootS3)
        .when()
                .get("/" + LOG_BUCKET + "?list-type=2&prefix=" + prefix)
        .then()
                .statusCode(200)
                .body("ListBucketResult.Contents.size()", greaterThan(0))
                .body("ListBucketResult.Contents[0].Key", equalTo(objectKey));
    }

    private static String cloudTrailBucketPolicy(String bucket, String trailName) {
        String trailArn = "arn:aws:cloudtrail:" + REGION + ":" + ACCOUNT + ":trail/" + trailName;
        return """
                {"Version":"2012-10-17","Statement":[
                  {"Sid":"AWSCloudTrailAclCheck","Effect":"Allow",
                   "Principal":{"Service":"cloudtrail.amazonaws.com"},
                   "Action":"s3:GetBucketAcl",
                   "Resource":"arn:aws:s3:::%s"},
                  {"Sid":"AWSCloudTrailWrite","Effect":"Allow",
                   "Principal":{"Service":"cloudtrail.amazonaws.com"},
                   "Action":"s3:PutObject",
                   "Resource":"arn:aws:s3:::%s/AWSLogs/%s/*",
                   "Condition":{"StringEquals":{"aws:SourceArn":"%s"}}}
                ]}\
                """.formatted(bucket, bucket, ACCOUNT, trailArn);
    }

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> overrides = new HashMap<>(new CtfLabIamEnforcementProfile().getConfigOverrides());
            overrides.put("floci.services.cloudtrail.audit-enabled", "true");
            return overrides;
        }
    }
}
