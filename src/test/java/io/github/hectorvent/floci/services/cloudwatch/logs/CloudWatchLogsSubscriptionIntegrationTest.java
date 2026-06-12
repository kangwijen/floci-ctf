package io.github.hectorvent.floci.services.cloudwatch.logs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.ByteArrayInputStream;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CloudWatchLogsSubscriptionIntegrationTest {

    private static final String LOGS_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String KINESIS_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String FIREHOSE_CONTENT_TYPE = "application/x-amz-json-1.1";

    private static final String LOG_GROUP = "/cwlogs/subscription-test";
    private static final String LOG_STREAM = "app-stream";
    private static final String KINESIS_STREAM = "cwlogs-subscription-kinesis";
    private static final String FIREHOSE_STREAM = "cwlogs-subscription-firehose";

    private static String kinesisStreamArn;
    private static String firehoseStreamArn;
    private static long eventTimestamp;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    @Order(1)
    void setupDestinations() {
        given()
            .header("X-Amz-Target", "Kinesis_20131202.CreateStream")
            .contentType(KINESIS_CONTENT_TYPE)
            .body("{\"StreamName\": \"" + KINESIS_STREAM + "\", \"ShardCount\": 1}")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        kinesisStreamArn = given()
            .header("X-Amz-Target", "Kinesis_20131202.DescribeStreamSummary")
            .contentType(KINESIS_CONTENT_TYPE)
            .body("{\"StreamName\": \"" + KINESIS_STREAM + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().jsonPath().getString("StreamDescriptionSummary.StreamARN");

        given()
            .contentType(FIREHOSE_CONTENT_TYPE)
            .header("X-Amz-Target", "Firehose_20150804.CreateDeliveryStream")
            .body("{\"DeliveryStreamName\": \"" + FIREHOSE_STREAM + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DeliveryStreamARN", notNullValue());

        firehoseStreamArn = given()
            .contentType(FIREHOSE_CONTENT_TYPE)
            .header("X-Amz-Target", "Firehose_20150804.DescribeDeliveryStream")
            .body("{\"DeliveryStreamName\": \"" + FIREHOSE_STREAM + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().jsonPath().getString("DeliveryStreamDescription.DeliveryStreamARN");
    }

    @Test
    @Order(2)
    void setupLogGroupStreamAndFilters() {
        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.CreateLogGroup")
            .body("{\"logGroupName\": \"" + LOG_GROUP + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.CreateLogStream")
            .body("{\"logGroupName\": \"" + LOG_GROUP + "\", \"logStreamName\": \"" + LOG_STREAM + "\"}")
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.PutSubscriptionFilter")
            .body("""
                {
                    "logGroupName": "%s",
                    "filterName": "error-filter",
                    "filterPattern": "ERROR",
                    "destinationArn": "%s"
                }
                """.formatted(LOG_GROUP, kinesisStreamArn))
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.PutSubscriptionFilter")
            .body("""
                {
                    "logGroupName": "%s",
                    "filterName": "all-filter",
                    "filterPattern": "*",
                    "destinationArn": "%s"
                }
                """.formatted(LOG_GROUP, firehoseStreamArn))
        .when()
            .post("/")
        .then()
            .statusCode(200);
    }

    @Test
    @Order(3)
    void putLogEventsDeliversMatchingEventsToKinesis() throws Exception {
        eventTimestamp = System.currentTimeMillis();

        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.PutLogEvents")
            .body("""
                {
                    "logGroupName": "%s",
                    "logStreamName": "%s",
                    "logEvents": [
                        {"timestamp": %d, "message": "INFO: started"},
                        {"timestamp": %d, "message": "ERROR: disk full"}
                    ]
                }
                """.formatted(LOG_GROUP, LOG_STREAM, eventTimestamp, eventTimestamp + 1))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("nextSequenceToken", notNullValue());

        String shardIterator = given()
            .header("X-Amz-Target", "Kinesis_20131202.GetShardIterator")
            .contentType(KINESIS_CONTENT_TYPE)
            .body("""
                {"StreamName": "%s", "ShardId": "shardId-000000000000", "ShardIteratorType": "TRIM_HORIZON"}
                """.formatted(KINESIS_STREAM))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().jsonPath().getString("ShardIterator");

        Response recordsResponse = given()
            .header("X-Amz-Target", "Kinesis_20131202.GetRecords")
            .contentType(KINESIS_CONTENT_TYPE)
            .body("{\"ShardIterator\": \"" + shardIterator + "\", \"Limit\": 10}")
        .when()
            .post("/");

        recordsResponse.then().statusCode(200);
        assertTrue(recordsResponse.jsonPath().getInt("Records.size()") >= 1,
                "Expected at least one Kinesis record from subscription filter delivery");

        String encodedData = recordsResponse.jsonPath().getString("Records[0].Data");
        JsonNode payload = decodeGzipJson(Base64.getDecoder().decode(encodedData));

        assertEquals("DATA_MESSAGE", payload.get("messageType").asText());
        assertEquals(LOG_GROUP, payload.get("logGroup").asText());
        assertEquals(LOG_STREAM, payload.get("logStream").asText());
        assertEquals("error-filter", payload.get("subscriptionFilters").get(0).asText());
        assertEquals(1, payload.get("logEvents").size());
        assertEquals("ERROR: disk full", payload.get("logEvents").get(0).get("message").asText());
        assertNotNull(payload.get("logEvents").get(0).get("id"));
        assertEquals(eventTimestamp + 1, payload.get("logEvents").get(0).get("timestamp").asLong());
        assertNotNull(payload.get("owner"));
    }

    @Test
    @Order(4)
    void nonMatchingEventsAreNotDeliveredToKinesis() {
        int beforeCount = kinesisRecordCount();

        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.PutLogEvents")
            .body("""
                {
                    "logGroupName": "%s",
                    "logStreamName": "%s",
                    "logEvents": [
                        {"timestamp": %d, "message": "INFO: healthy"}
                    ]
                }
                """.formatted(LOG_GROUP, LOG_STREAM, System.currentTimeMillis()))
        .when()
            .post("/")
        .then()
            .statusCode(200);

        int afterCount = kinesisRecordCount();
        assertEquals(beforeCount, afterCount, "Non-matching log events must not create new Kinesis records");
    }

    @Test
    @Order(5)
    void wildcardFilterDeliversToFirehoseWithoutError() {
        long ts = System.currentTimeMillis();
        given()
            .contentType(LOGS_CONTENT_TYPE)
            .header("X-Amz-Target", "Logs_20140328.PutLogEvents")
            .body("""
                {
                    "logGroupName": "%s",
                    "logStreamName": "%s",
                    "logEvents": [
                        {"timestamp": %d, "message": "audit event"}
                    ]
                }
                """.formatted(LOG_GROUP, LOG_STREAM, ts))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("nextSequenceToken", notNullValue());
    }

    private int kinesisRecordCount() {
        String shardIterator = given()
            .header("X-Amz-Target", "Kinesis_20131202.GetShardIterator")
            .contentType(KINESIS_CONTENT_TYPE)
            .body("""
                {"StreamName": "%s", "ShardId": "shardId-000000000000", "ShardIteratorType": "TRIM_HORIZON"}
                """.formatted(KINESIS_STREAM))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().jsonPath().getString("ShardIterator");

        return given()
            .header("X-Amz-Target", "Kinesis_20131202.GetRecords")
            .contentType(KINESIS_CONTENT_TYPE)
            .body("{\"ShardIterator\": \"" + shardIterator + "\", \"Limit\": 100}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().jsonPath().getInt("Records.size()");
    }

    private static JsonNode decodeGzipJson(byte[] gzipData) throws Exception {
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(gzipData))) {
            return new ObjectMapper().readTree(gzip.readAllBytes());
        }
    }
}
