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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SQS Query API calls record {@code queueUrl}, {@code eventTime}, and {@code sourceIPAddress}
 * in CloudTrail audit events for lookup.
 */
@QuarkusTest
@TestProfile(CloudTrailForwardedHeadersAuditProfile.class)
class CloudTrailSqsAuditIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String CLOUDTRAIL_TARGET =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String SQS_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/sqs/aws4_request";
    private static final String IAM_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/iam/aws4_request";

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
    void sqsReceiveSendPurgeRecordQueueUrlEventTimeAndSourceIp() throws Exception {
        String trailBucket = "sqs-audit-trail-bucket";
        String trailName = "sqs-audit-trail";
        String queueName = "sqs-audit-queue";

        provisionLoggingTrail(trailBucket, trailName);

        String queueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", queueName)
                .header("Authorization", SQS_AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        given()
                .formParam("Action", "SendMessage")
                .formParam("QueueUrl", queueUrl)
                .formParam("MessageBody", "inject-payload")
                .header("Authorization", SQS_AUTH)
                .header("X-Forwarded-For", "203.0.113.10")
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", queueUrl)
                .header("Authorization", SQS_AUTH)
                .header("X-Forwarded-For", "10.40.12.5")
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "PurgeQueue")
                .formParam("QueueUrl", queueUrl)
                .header("Authorization", SQS_AUTH)
                .header("X-Forwarded-For", "198.51.100.99")
                .when().post("/")
                .then().statusCode(200);

        JsonNode purgeEvent = lookupSingleEvent("PurgeQueue");
        assertEquals("sqs.amazonaws.com", purgeEvent.path("eventSource").asText());
        assertEquals(queueUrl, purgeEvent.path("requestParameters").path("queueUrl").asText());
        assertEquals("198.51.100.99", purgeEvent.path("sourceIPAddress").asText());
        assertEquals("Management", purgeEvent.path("eventCategory").asText());
        assertEquals(true, purgeEvent.path("managementEvent").asBoolean());
        assertTrue(purgeEvent.path("eventTime").asText().matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z"));
        assertEquals("AWS::SQS::Queue", purgeEvent.path("resources").get(0).path("type").asText());

        JsonNode receiveEvent = lookupSingleEvent("ReceiveMessage");
        assertEquals(queueUrl, receiveEvent.path("requestParameters").path("queueUrl").asText());
        assertEquals("10.40.12.5", receiveEvent.path("sourceIPAddress").asText());
        assertEquals("Data", receiveEvent.path("eventCategory").asText());
        assertEquals(false, receiveEvent.path("managementEvent").asBoolean());
        assertEquals(true, receiveEvent.path("readOnly").asBoolean());

        JsonNode sendEvent = lookupSingleEvent("SendMessage");
        assertEquals(queueUrl, sendEvent.path("requestParameters").path("queueUrl").asText());
        assertEquals("203.0.113.10", sendEvent.path("sourceIPAddress").asText());
        assertEquals("Data", sendEvent.path("eventCategory").asText());
        assertEquals("HIDDEN_DUE_TO_SECURITY_REASONS",
                sendEvent.path("requestParameters").path("messageBody").asText());
        assertNotNull(sendEvent.path("responseElements").path("messageId").asText(null));
    }

    @Test
    void sqsAssumedRoleRecordsSessionContext() throws Exception {
        String trailBucket = "sqs-assume-audit-bucket";
        String trailName = "sqs-assume-audit-trail";
        String queueName = "sqs-assume-audit-queue";
        String roleName = "sqs-audit-runner";
        String callerUser = "sqs-audit-caller";

        provisionLoggingTrail(trailBucket, trailName);

        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", callerUser)
                .when().post("/")
                .then().statusCode(200);

        String callerAkid = given()
                .formParam("Action", "CreateAccessKey")
                .formParam("UserName", callerUser)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");

        String callerArn = "arn:aws:iam::000000000000:user/" + callerUser;
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument",
                        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                                + "\"Principal\":{\"AWS\":\"" + callerArn + "\"},"
                                + "\"Action\":\"sts:AssumeRole\"}]}")
                .header("Authorization", IAM_AUTH)
                .when().post("/")
                .then().statusCode(200);

        String roleArn = "arn:aws:iam::000000000000:role/" + roleName;
        String callerStsAuth = "AWS4-HMAC-SHA256 Credential=" + callerAkid
                + "/20260227/us-east-1/sts/aws4_request";
        String sessionAkid = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "audit-test-session")
                .header("Authorization", callerStsAuth)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
        String sessionToken = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "audit-test-session")
                .header("Authorization", callerStsAuth)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken");

        String queueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", queueName)
                .header("Authorization", SQS_AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        String sessionSqsAuth = "AWS4-HMAC-SHA256 Credential=" + sessionAkid
                + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", queueUrl)
                .header("Authorization", sessionSqsAuth)
                .header("X-Amz-Security-Token", sessionToken)
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("ReceiveMessage");
        JsonNode identity = event.path("userIdentity");
        assertEquals("AssumedRole", identity.path("type").asText());
        assertTrue(identity.path("arn").asText().contains(":assumed-role/" + roleName + "/"));
        assertNotNull(identity.path("sessionContext").path("sessionIssuer").path("arn").asText());
        assertEquals(roleArn, identity.path("sessionContext").path("sessionIssuer").path("arn").asText());
    }

    private void provisionLoggingTrail(String trailBucket, String trailName) {
        given().when().put("/" + trailBucket).then().statusCode(200);
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\",\"S3BucketName\":\"%s\"}".formatted(trailName, trailBucket))
        .when()
                .post("/")
        .then()
                .statusCode(200);
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\"}".formatted(trailName))
        .when()
                .post("/")
        .then()
                .statusCode(200);
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
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo(eventName))
                .body("Events[0].EventSource", equalTo("sqs.amazonaws.com"))
                .extract().path("Events[0].CloudTrailEvent");
        return objectMapper.readTree(cloudTrailJson);
    }
}
