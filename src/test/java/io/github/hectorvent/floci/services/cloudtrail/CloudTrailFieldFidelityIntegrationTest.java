package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testsupport.CloudTrailForwardedHeadersAuditProfile;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * CloudTrail audit events preserve AWS-shaped request parameters for S3, STS, and Secrets Manager.
 */
@QuarkusTest
@TestProfile(CloudTrailForwardedHeadersAuditProfile.class)
class CloudTrailFieldFidelityIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String CLOUDTRAIL_TARGET =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String S3_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/s3/aws4_request";
    private static final String STS_AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/sts/aws4_request";
    private static final String SM_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/secretsmanager/aws4_request";

    @Inject
    CloudTrailEventStore eventStore;

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
    void s3StsAndSecretsManagerRecordRequestParameters() throws Exception {
        String trailBucket = "audit-trail-logs-bucket";
        String trailName = "audit-trail";
        String dataBucket = "audit-data-bucket";
        String objectKey = "sample-object.txt";
        String secretName = "app/sample-secret";
        String roleArn = "arn:aws:iam::000000000000:role/TestRole";
        String sessionName = "audit-test-session";

        provisionLoggingTrail(trailBucket, trailName);

        given().when().put("/" + dataBucket).then().statusCode(200);

        given()
                .header("Authorization", S3_AUTH)
                .body("sample payload")
                .when().put("/" + dataBucket + "/" + objectKey)
                .then().statusCode(200);

        given()
                .header("Authorization", S3_AUTH)
                .when().delete("/" + dataBucket + "/" + objectKey)
                .then().statusCode(204);

        given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", sessionName)
                .header("Authorization", STS_AUTH)
                .when().post("/");

        given()
                .header("Authorization", SM_AUTH)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\",\"SecretString\":\"sample-value\"}".formatted(secretName))
                .when().post("/")
                .then().statusCode(200);

        given()
                .header("Authorization", SM_AUTH)
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType(CONTENT_TYPE)
                .body("{\"SecretId\":\"%s\"}".formatted(secretName))
                .when().post("/")
                .then().statusCode(200);

        JsonNode putEvent = lookupSingleEvent("PutObject", "s3.amazonaws.com");
        assertEquals("PutObject", putEvent.path("eventName").asText());
        assertEquals(dataBucket, putEvent.path("requestParameters").path("bucketName").asText());
        assertEquals(objectKey, putEvent.path("requestParameters").path("key").asText());
        assertEquals("Data", putEvent.path("eventCategory").asText());
        assertEquals(false, putEvent.path("managementEvent").asBoolean());
        assertEquals("AWS::S3::Object", putEvent.path("resources").get(0).path("type").asText());
        assertEquals("arn:aws:s3:::" + dataBucket + "/" + objectKey,
                putEvent.path("resources").get(0).path("ARN").asText());

        JsonNode deleteEvent = lookupSingleEvent("DeleteObject", "s3.amazonaws.com");
        assertEquals("DeleteObject", deleteEvent.path("eventName").asText());
        assertEquals(dataBucket, deleteEvent.path("requestParameters").path("bucketName").asText());
        assertEquals(objectKey, deleteEvent.path("requestParameters").path("key").asText());
        assertEquals("Data", deleteEvent.path("eventCategory").asText());

        JsonNode assumeEvent = lookupSingleEvent("AssumeRole", "sts.amazonaws.com");
        assertEquals(roleArn, assumeEvent.path("requestParameters").path("roleArn").asText());
        assertEquals(sessionName, assumeEvent.path("requestParameters").path("roleSessionName").asText());
        assertEquals("Management", assumeEvent.path("eventCategory").asText());
        assertEquals(true, assumeEvent.path("readOnly").asBoolean());
        assertEquals("AWS::IAM::Role", assumeEvent.path("resources").get(0).path("type").asText());

        JsonNode secretEvent = lookupSingleEvent("GetSecretValue", "secretsmanager.amazonaws.com");
        assertEquals(secretName, secretEvent.path("requestParameters").path("secretId").asText());
        assertEquals("Management", secretEvent.path("eventCategory").asText());
        assertEquals("AWS::SecretsManager::Secret", secretEvent.path("resources").get(0).path("type").asText());
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

    private JsonNode lookupSingleEvent(String eventName, String eventSource) throws Exception {
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
                .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo(eventName))
                .body("Events[0].EventSource", equalTo(eventSource))
                .extract().path("Events[0].CloudTrailEvent");
        return objectMapper.readTree(cloudTrailJson);
    }
}
