package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S3 access log delivery with IAM enforcement: destination bucket policy must allow
 * {@code logging.s3.amazonaws.com} with {@code aws:SourceArn} / {@code aws:SourceAccount}.
 */
@QuarkusTest
@TestProfile(S3AccessLogDeliveryIamIntegrationTest.Profile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class S3AccessLogDeliveryIamIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String SOURCE_BUCKET = "ctf-access-log-source";
    private static final String LOG_BUCKET = "ctf-access-log-target";
    private static final String LOG_PREFIX = "access-logs/";
    private static final String OBJECT_KEY = "probe.txt";

    @TestHTTPResource("/")
    URL endpoint;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String rootS3 = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3");

        given().header("Authorization", rootS3).when().put("/" + LOG_BUCKET).then().statusCode(200);
        given().header("Authorization", rootS3).when().put("/" + SOURCE_BUCKET).then().statusCode(200);

        given()
                .header("Authorization", rootS3)
                .contentType("application/json")
                .body(loggingBucketPolicy(LOG_BUCKET, SOURCE_BUCKET))
        .when()
                .put("/" + LOG_BUCKET + "?policy")
        .then()
                .statusCode(200);

        String loggingXml = """
                <BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <LoggingEnabled>
                        <TargetBucket>%s</TargetBucket>
                        <TargetPrefix>%s</TargetPrefix>
                    </LoggingEnabled>
                </BucketLoggingStatus>
                """.formatted(LOG_BUCKET, LOG_PREFIX);

        given()
                .header("Authorization", rootS3)
                .queryParam("logging", "")
                .contentType("application/xml")
                .body(loggingXml)
        .when()
                .put("/" + SOURCE_BUCKET)
        .then()
                .statusCode(200);
    }

    @Test
    @Order(1)
    void objectPutDeliversAccessLogWhenBucketPolicyAllowsLoggingService() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3"))
                .contentType("text/plain")
                .body("payload")
        .when()
                .put("/" + SOURCE_BUCKET + "/" + OBJECT_KEY)
        .then()
                .statusCode(200);

        List<String> keys = given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3"))
                .queryParam("prefix", LOG_PREFIX)
        .when()
                .get("/" + LOG_BUCKET)
        .then()
                .statusCode(200)
                .body("ListBucketResult.Contents.size()", greaterThanOrEqualTo(1))
                .extract()
                .xmlPath()
                .getList("ListBucketResult.Contents.Key", String.class);

        assertTrue(keys.stream().anyMatch(key ->
                        Pattern.compile("access-logs/\\d{4}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-[0-9a-f]{16}")
                                .matcher(key).find()),
                "expected AWS simple-prefix log object key, got: " + keys);

        String logBody = given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3"))
        .when()
                .get("/" + LOG_BUCKET + "/" + keys.getFirst())
        .then()
                .statusCode(200)
                .extract()
                .asString();

        assertTrue(logBody.contains("REST.PUT.OBJECT"));
        assertTrue(logBody.contains(OBJECT_KEY));
    }

    private static String loggingBucketPolicy(String logBucket, String sourceBucket) {
        return """
                {"Version":"2012-10-17","Statement":[
                  {"Sid":"S3ServerAccessLogsPolicy","Effect":"Allow",
                   "Principal":{"Service":"logging.s3.amazonaws.com"},
                   "Action":["s3:PutObject"],
                   "Resource":"arn:aws:s3:::%s/%s*",
                   "Condition":{
                     "ArnLike":{"aws:SourceArn":"arn:aws:s3:::%s"},
                     "StringEquals":{"aws:SourceAccount":"%s"}
                   }}
                ]}\
                """.formatted(logBucket, LOG_PREFIX, sourceBucket, ACCOUNT);
    }

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return new CtfLabIamEnforcementProfile().getConfigOverrides();
        }
    }
}
