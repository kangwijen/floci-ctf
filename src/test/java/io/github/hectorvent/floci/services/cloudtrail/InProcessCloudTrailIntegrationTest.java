package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.apigateway.AwsServiceRouter;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.firehose.model.DeliveryStreamDescription;
import io.github.hectorvent.floci.services.firehose.model.Record;
import io.github.hectorvent.floci.services.firehose.FirehoseService;
import io.github.hectorvent.floci.testsupport.CloudTrailAuditProfile;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertThrows;

@QuarkusTest
@TestProfile(CloudTrailAuditProfile.class)
class InProcessCloudTrailIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String REGION = "us-east-1";
    private static final String TRAIL_BUCKET = "inprocess-cloudtrail-logs";
    private static final String TRAIL_NAME = "inprocess-audit-trail";
    private static final String FIREHOSE_STREAM = "inprocess-firehose-stream";
    private static final String FIREHOSE_BUCKET = "inprocess-firehose-target";

    @Inject
    CloudTrailDeliveryService deliveryService;

    @Inject
    CloudTrailEventStore eventStore;

    @Inject
    FirehoseService firehoseService;

    @Inject
    AwsServiceRouter awsServiceRouter;

    @Inject
    InProcessCloudTrailRecorder inProcessCloudTrailRecorder;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @BeforeEach
    void resetStores() {
        eventStore.clear();
        deliveryService.setBufferSizeForTests(1);
        ensureTrailLogging();
    }

    private static boolean trailProvisioned;

    private void ensureTrailLogging() {
        given().when().put("/" + TRAIL_BUCKET).then().statusCode(200);

        if (!trailProvisioned) {
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
                            """.formatted(TRAIL_NAME, TRAIL_BUCKET))
            .when()
                    .post("/")
            .then()
                    .statusCode(200);
            trailProvisioned = true;
        }

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s"
                        }
                        """.formatted(TRAIL_NAME))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    @Test
    void firehoseFlushRecordsS3PutObjectAsAwsServiceEvent() {
        DeliveryStreamDescription.S3Destination s3Destination = new DeliveryStreamDescription.S3Destination();
        s3Destination.setBucketArn("arn:aws:s3:::" + FIREHOSE_BUCKET);
        s3Destination.setPrefix(FIREHOSE_STREAM + "/");
        firehoseService.createDeliveryStream(FIREHOSE_STREAM, s3Destination);
        firehoseService.putRecord(FIREHOSE_STREAM, new Record("line-one".getBytes(StandardCharsets.UTF_8)));
        firehoseService.putRecord(FIREHOSE_STREAM, new Record("line-two".getBytes(StandardCharsets.UTF_8)));
        firehoseService.putRecord(FIREHOSE_STREAM, new Record("line-three".getBytes(StandardCharsets.UTF_8)));
        firehoseService.putRecord(FIREHOSE_STREAM, new Record("line-four".getBytes(StandardCharsets.UTF_8)));
        firehoseService.putRecord(FIREHOSE_STREAM, new Record("line-five".getBytes(StandardCharsets.UTF_8)));
        firehoseService.flush(FIREHOSE_STREAM);
        deliveryService.flushAll();

        lookupEvent("PutObject", "s3.amazonaws.com")
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo("PutObject"))
                .body("Events[0].EventSource", equalTo("s3.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("firehose.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("\"type\":\"AWSService\""))
                .body("Events[0].CloudTrailEvent", containsString("\"eventCategory\":\"Data\""));
    }

    @Test
    void directRecorderBuildsAssumedRoleIdentityForApigwStyleCall() {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("TableName", "inprocess-table");

        inProcessCloudTrailRecorder.record(InProcessAuditContext.builder()
                .region(REGION)
                .eventName("PutItem")
                .credentialScope("dynamodb")
                .requestParameters(Map.of("TableName", "inprocess-table"))
                .invokedBy("apigateway.amazonaws.com")
                .executionRoleArn("arn:aws:iam::000000000000:role/InProcessTestRole")
                .build());

        deliveryService.flushAll();

        lookupEvent("PutItem", "dynamodb.amazonaws.com")
                .body("Events", hasSize(1))
                .body("Events[0].CloudTrailEvent", containsString("apigateway.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("\"type\":\"AssumedRole\""))
                .body("Events[0].CloudTrailEvent", containsString("InProcessTestRole"));
    }

    @Test
    void apigwRouterRecordsManagementEventAfterHandlerInvoke() {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("TableName", "router-table");
        body.set("Item", objectMapper.createObjectNode().put("id", objectMapper.createObjectNode().put("S", "1")));

        assertThrows(AwsException.class,
                () -> awsServiceRouter.invoke("dynamodb", "PutItem", body, REGION, null));

        deliveryService.flushAll();

        lookupEvent("PutItem", "dynamodb.amazonaws.com")
                .body("Events", hasSize(1))
                .body("Events[0].CloudTrailEvent", containsString("apigateway.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("ResourceNotFoundException"));
    }

    private io.restassured.response.ValidatableResponse lookupEvent(String eventName, String eventSource) {
        return given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
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
                .body("Events[0].EventSource", equalTo(eventSource));
    }
}
