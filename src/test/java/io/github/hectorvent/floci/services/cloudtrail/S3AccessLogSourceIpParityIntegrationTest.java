package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.testsupport.CloudTrailForwardedHeadersAuditProfile;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * S3 server access log Remote IP matches CloudTrail {@code sourceIPAddress} when
 * {@code X-Forwarded-For} is trusted.
 */
@QuarkusTest
@TestProfile(CloudTrailForwardedHeadersAuditProfile.class)
class S3AccessLogSourceIpParityIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String CLOUDTRAIL_TARGET =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String S3_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/s3/aws4_request";
    private static final String SOURCE_IP = "203.0.113.55";

    @Inject
    CloudTrailEventStore eventStore;

    @Inject
    S3Service s3Service;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @BeforeEach
    void resetStore() {
        eventStore.clear();
    }

    @Test
    void getObjectAccessLogRemoteIpMatchesCloudTrailSourceIp() throws Exception {
        String dataBucket = "source-ip-data-bucket";
        String logBucket = "source-ip-log-bucket";
        String objectKey = "evidence/object.txt";
        String logPrefix = "access/";

        provisionLoggingTrail("source-ip-trail-bucket", "source-ip-trail");
        given().when().put("/" + dataBucket).then().statusCode(200);
        given().when().put("/" + logBucket).then().statusCode(200);

        String loggingXml = """
                <BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                  <LoggingEnabled>
                    <TargetBucket>%s</TargetBucket>
                    <TargetPrefix>%s</TargetPrefix>
                  </LoggingEnabled>
                </BucketLoggingStatus>
                """.formatted(logBucket, logPrefix);

        given()
                .header("Authorization", S3_AUTH)
                .contentType("application/xml")
                .body(loggingXml)
                .when().put("/" + dataBucket + "?logging")
                .then().statusCode(200);

        given()
                .header("Authorization", S3_AUTH)
                .header("X-Forwarded-For", SOURCE_IP)
                .body("payload")
                .when().put("/" + dataBucket + "/" + objectKey)
                .then().statusCode(200);

        given()
                .header("Authorization", S3_AUTH)
                .header("X-Forwarded-For", SOURCE_IP)
                .when().get("/" + dataBucket + "/" + objectKey)
                .then().statusCode(200);

        JsonNode getObjectEvent = lookupSingleEvent("GetObject");
        assertEquals(SOURCE_IP, getObjectEvent.path("sourceIPAddress").asText());

        List<String> logKeys = s3Service.listObjects(logBucket, logPrefix, null, 100).stream()
                .map(obj -> obj.getKey())
                .filter(key -> key.startsWith(logPrefix))
                .toList();
        assertTrue(!logKeys.isEmpty(), "expected access log objects");

        String combinedLogBody = logKeys.stream()
                .map(key -> new String(s3Service.getObject(logBucket, key).getData(), StandardCharsets.UTF_8))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("");
        String getObjectLine = combinedLogBody.lines()
                .filter(line -> line.contains("REST.GET.OBJECT"))
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "REST.GET.OBJECT line missing in access log objects: " + logKeys));
        assertEquals(SOURCE_IP, remoteIpFromAccessLogLine(getObjectLine),
                "Remote IP field should match CloudTrail sourceIPAddress");
    }

    private static String remoteIpFromAccessLogLine(String line) {
        int timeStart = line.indexOf('[');
        if (timeStart < 0) {
            return null;
        }
        int timeEnd = line.indexOf(']', timeStart);
        if (timeEnd < 0 || timeEnd + 1 >= line.length()) {
            return null;
        }
        String afterTime = line.substring(timeEnd + 1).stripLeading();
        int space = afterTime.indexOf(' ');
        return space < 0 ? afterTime : afterTime.substring(0, space);
    }

    private void provisionLoggingTrail(String trailBucket, String trailName) {
        given().when().put("/" + trailBucket).then().statusCode(200);
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\",\"S3BucketName\":\"%s\"}".formatted(trailName, trailBucket))
                .when().post("/")
                .then().statusCode(200);
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\"}".formatted(trailName))
                .when().post("/")
                .then().statusCode(200);
    }

    private JsonNode lookupSingleEvent(String eventName) throws Exception {
        String cloudTrailJson = given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {"AttributeKey": "EventName", "AttributeValue": "%s"}
                            ]
                        }
                        """.formatted(eventName))
                .when().post("/")
                .then().statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo(eventName))
                .extract().path("Events[0].CloudTrailEvent");
        return objectMapper.readTree(cloudTrailJson);
    }
}
