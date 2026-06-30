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
 * DynamoDB JSON {@code PutItem} records {@code requestParameters.tableName} in CloudTrail audit events.
 */
@QuarkusTest
@TestProfile(CloudTrailForwardedHeadersAuditProfile.class)
class CloudTrailDynamoDbPutItemAuditIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String DYNAMODB_CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String CLOUDTRAIL_TARGET =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String DDB_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/dynamodb/aws4_request";
    private static final String TABLE = "audit-events-table";

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
    void putItemRecordsTableNameAndResource() throws Exception {
        provisionLoggingTrail("ddb-audit-trail-bucket", "ddb-audit-trail");

        given()
                .header("Authorization", DDB_AUTH)
                .header("X-Amz-Target", "DynamoDB_20120810.CreateTable")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                          "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                          "BillingMode": "PAY_PER_REQUEST"
                        }""".formatted(TABLE))
                .when().post("/")
                .then().statusCode(200);

        given()
                .header("Authorization", DDB_AUTH)
                .header("X-Amz-Target", "DynamoDB_20120810.PutItem")
                .header("X-Forwarded-For", "10.20.30.40")
                .contentType(DYNAMODB_CONTENT_TYPE)
                .body("""
                        {
                          "TableName": "%s",
                          "Item": {"pk": {"S": "row-1"}, "data": {"S": "value"}}
                        }""".formatted(TABLE))
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("PutItem");
        assertEquals("dynamodb.amazonaws.com", event.path("eventSource").asText());
        assertEquals(TABLE, event.path("requestParameters").path("tableName").asText());
        assertEquals("10.20.30.40", event.path("sourceIPAddress").asText());
        assertEquals("AWS::DynamoDB::Table", event.path("resources").get(0).path("type").asText());
        assertEquals("arn:aws:dynamodb:us-east-1:000000000000:table/" + TABLE,
                event.path("resources").get(0).path("ARN").asText());
        assertEquals("000000000000", event.path("resources").get(0).path("accountId").asText());
        assertEquals("Management", event.path("eventCategory").asText());
        assertTrue(event.path("managementEvent").asBoolean());
        assertFalse(event.path("readOnly").asBoolean());
        assertFalse(event.path("requestParameters").has("Item"));
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
                .body("Events[0].EventSource", equalTo("dynamodb.amazonaws.com"))
                .extract().path("Events[0].CloudTrailEvent");
        return objectMapper.readTree(cloudTrailJson);
    }
}
