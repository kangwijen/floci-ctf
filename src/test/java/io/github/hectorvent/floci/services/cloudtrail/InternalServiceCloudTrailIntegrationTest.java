package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.services.firehose.FirehoseService;
import io.github.hectorvent.floci.testsupport.CloudTrailAuditProfile;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@TestProfile(CloudTrailAuditProfile.class)
class InternalServiceCloudTrailIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String CLOUDTRAIL_TARGET = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String LOGS_TARGET = "Logs_20140328.";
    private static final String FIREHOSE_TARGET = "Firehose_20150804.";

    private static final String TRAIL_BUCKET = "internal-cloudtrail-trail-bucket";
    private static final String FIREHOSE_BUCKET = "internal-cloudtrail-firehose-bucket";
    private static final String TRAIL_NAME = "internal-service-trail";
    private static final String LOG_GROUP = "/internal/cloudtrail/firehose";
    private static final String LOG_STREAM = "app";
    private static final String FIREHOSE_STREAM = "internal-cloudtrail-firehose";

    @Inject
    CloudTrailDeliveryService deliveryService;

    @Inject
    CloudTrailEventStore eventStore;

    @Inject
    FirehoseService firehoseService;

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
    void firehoseFlushRecordsS3PutObjectInLookupEvents() {
        given().when().put("/" + TRAIL_BUCKET).then().statusCode(200);
        given().when().put("/" + FIREHOSE_BUCKET).then().statusCode(200);

        createTrailAndStartLogging();

        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", FIREHOSE_TARGET + "CreateDeliveryStream")
                .body("""
                        {
                            "DeliveryStreamName": "%s",
                            "ExtendedS3DestinationConfiguration": {
                                "BucketARN": "arn:aws:s3:::%s",
                                "RoleARN": "arn:aws:iam::000000000000:role/firehose-delivery",
                                "Prefix": "firehose-output/"
                            }
                        }
                        """.formatted(FIREHOSE_STREAM, FIREHOSE_BUCKET))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", LOGS_TARGET + "CreateLogGroup")
                .body("{\"logGroupName\": \"" + LOG_GROUP + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", LOGS_TARGET + "CreateLogStream")
                .body("""
                        {"logGroupName": "%s", "logStreamName": "%s"}
                        """.formatted(LOG_GROUP, LOG_STREAM))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        String firehoseArn = given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", FIREHOSE_TARGET + "DescribeDeliveryStream")
                .body("{\"DeliveryStreamName\": \"" + FIREHOSE_STREAM + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract().jsonPath().getString("DeliveryStreamDescription.DeliveryStreamARN");

        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", LOGS_TARGET + "PutSubscriptionFilter")
                .body("""
                        {
                            "logGroupName": "%s",
                            "filterName": "all",
                            "filterPattern": "*",
                            "destinationArn": "%s"
                        }
                        """.formatted(LOG_GROUP, firehoseArn))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        long timestamp = System.currentTimeMillis();
        given()
                .contentType(CONTENT_TYPE)
                .header("X-Amz-Target", LOGS_TARGET + "PutLogEvents")
                .body("""
                        {
                            "logGroupName": "%s",
                            "logStreamName": "%s",
                            "logEvents": [
                                {"timestamp": %d, "message": "internal audit probe"}
                            ]
                        }
                        """.formatted(LOG_GROUP, LOG_STREAM, timestamp))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("nextSequenceToken", notNullValue());

        firehoseService.flush(FIREHOSE_STREAM);
        deliveryService.flushAll();

        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "LookupEvents")
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
                .body("Events.size()", greaterThanOrEqualTo(1))
                .body("Events[0].EventName", equalTo("PutObject"))
                .body("Events[0].EventSource", equalTo("s3.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("firehose.amazonaws.com"))
                .body("Events[0].CloudTrailEvent", containsString("AWSService"));
    }

    private void createTrailAndStartLogging() {
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "CreateTrail")
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

        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "StartLogging")
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
}
