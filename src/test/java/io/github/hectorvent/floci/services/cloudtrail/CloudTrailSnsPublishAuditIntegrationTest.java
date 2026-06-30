package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testsupport.CloudTrailForwardedHeadersAuditProfile;
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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SNS Query {@code Publish} records {@code requestParameters.topicArn} in CloudTrail audit events.
 */
@QuarkusTest
@TestProfile(CloudTrailForwardedHeadersAuditProfile.class)
class CloudTrailSnsPublishAuditIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String CLOUDTRAIL_TARGET =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String SNS_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/sns/aws4_request";

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
    void publishRecordsTopicArnEventTimeAndSourceIp() throws Exception {
        provisionLoggingTrail("sns-audit-trail-bucket", "sns-audit-trail");

        String topicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", "audit-publish-topic")
                .header("Authorization", SNS_AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "audit-message-body")
                .header("Authorization", SNS_AUTH)
                .header("X-Forwarded-For", "198.51.100.77")
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("Publish");
        assertEquals("sns.amazonaws.com", event.path("eventSource").asText());
        assertEquals(topicArn, event.path("requestParameters").path("topicArn").asText());
        assertEquals("198.51.100.77", event.path("sourceIPAddress").asText());
        assertEquals("Management", event.path("eventCategory").asText());
        assertEquals("AWS::SNS::Topic", event.path("resources").get(0).path("type").asText());
    }

    @Test
    void publishJsonRecordsTopicArnAndManagementEvent() throws Exception {
        provisionLoggingTrail("sns-json-audit-trail-bucket", "sns-json-audit-trail");

        String topicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", "json-audit-publish-topic")
                .header("Authorization", SNS_AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        given()
                .header("Authorization", SNS_AUTH)
                .header("X-Amz-Target", "SNS_20100331.Publish")
                .contentType("application/x-amz-json-1.0")
                .body("""
                        {"TopicArn":"%s","Message":"json-audit-message"}
                        """.formatted(topicArn))
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("Publish");
        assertEquals(topicArn, event.path("requestParameters").path("topicArn").asText());
        assertEquals(topicArn, event.path("resources").get(0).path("ARN").asText());
        assertEquals("Management", event.path("eventCategory").asText());
        assertTrue(event.path("managementEvent").asBoolean());
        assertFalse(event.path("readOnly").asBoolean());
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
                .body("Events[0].EventSource", equalTo("sns.amazonaws.com"))
                .extract().path("Events[0].CloudTrailEvent");
        return objectMapper.readTree(cloudTrailJson);
    }
}
