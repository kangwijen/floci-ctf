package io.github.hectorvent.floci.services.ec2;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

/**
 * Integration tests for VPC Flow Logs (CreateFlowLogs, DescribeFlowLogs, DeleteFlowLogs)
 * and synthetic record delivery to S3 and CloudWatch Logs.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class Ec2FlowLogsIntegrationTest {

    private static final String AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=test/20260205/us-east-1/ec2/aws4_request";

    private static final Pattern DEFAULT_V2_RECORD = Pattern.compile(
            "^2 000000000000 eni-[0-9a-f]+ (\\d{1,3}\\.){3}\\d{1,3} (\\d{1,3}\\.){3}\\d{1,3} "
                    + "\\d+ \\d+ 6 \\d+ \\d+ \\d+ \\d+ ACCEPT OK$");

    private static String s3FlowLogId;
    private static String cwFlowLogId;
    private static String s3ObjectKey;
    private static String instanceId;

    @Test
    @Order(1)
    void createS3BucketForFlowLogs() {
        given()
        .when()
            .put("/flow-logs-int-bucket")
        .then()
            .statusCode(200);
    }

    @Test
    @Order(2)
    void createVpcFlowLogToS3() {
        s3FlowLogId = given()
            .formParam("Action", "CreateFlowLogs")
            .formParam("ResourceType", "VPC")
            .formParam("ResourceId.1", "vpc-default")
            .formParam("TrafficType", "ALL")
            .formParam("LogDestinationType", "s3")
            .formParam("LogDestination", "arn:aws:s3:::flow-logs-int-bucket/flow-logs/")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .contentType("application/xml")
            .body("CreateFlowLogsResponse.flowLogIdSet.item", startsWith("fl-"))
            .body("CreateFlowLogsResponse.unsuccessful.item.size()", equalTo(0))
            .extract().path("CreateFlowLogsResponse.flowLogIdSet.item");

        String datePath = DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC)
                .format(java.time.Instant.now());
        String dayStamp = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC)
                .format(java.time.Instant.now());
        s3ObjectKey = "flow-logs/AWSLogs/000000000000/vpcflowlogs/us-east-1/" + datePath + "/"
                + "000000000000_vpcflowlogs_us-east-1_" + dayStamp + "_" + s3FlowLogId + ".log";
    }

    @Test
    @Order(3)
    void describeVpcFlowLog() {
        given()
            .formParam("Action", "DescribeFlowLogs")
            .formParam("FlowLogId.1", s3FlowLogId)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .contentType("application/xml")
            .body("DescribeFlowLogsResponse.flowLogSet.item[0].flowLogId", equalTo(s3FlowLogId))
            .body("DescribeFlowLogsResponse.flowLogSet.item[0].resourceId", equalTo("vpc-default"))
            .body("DescribeFlowLogsResponse.flowLogSet.item[0].logDestinationType", equalTo("s3"))
            .body("DescribeFlowLogsResponse.flowLogSet.item[0].trafficType", equalTo("ALL"))
            .body("DescribeFlowLogsResponse.flowLogSet.item[0].flowLogStatus", equalTo("ACTIVE"))
            .body("DescribeFlowLogsResponse.flowLogSet.item[0].deliverLogsStatus", equalTo("SUCCESS"));
    }

    @Test
    @Order(4)
    void runInstanceGeneratesFlowLogRecordsToS3() {
        instanceId = given()
            .formParam("Action", "RunInstances")
            .formParam("ImageId", "ami-amazonlinux2023")
            .formParam("InstanceType", "t2.micro")
            .formParam("MinCount", "1")
            .formParam("MaxCount", "1")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().path("RunInstancesResponse.instancesSet.item.instanceId");

        String body = given()
        .when()
            .get("/flow-logs-int-bucket/" + s3ObjectKey)
        .then()
            .statusCode(200)
            .extract().asString();

        String[] lines = body.strip().split("\n");
        org.junit.jupiter.api.Assertions.assertTrue(lines.length >= 1);
        org.junit.jupiter.api.Assertions.assertTrue(
                DEFAULT_V2_RECORD.matcher(lines[lines.length - 1].trim()).matches(),
                "Expected AWS default VPC flow log v2 record, got: " + lines[lines.length - 1]);
    }

    @Test
    @Order(5)
    void createVpcFlowLogToCloudWatchLogs() {
        cwFlowLogId = given()
            .formParam("Action", "CreateFlowLogs")
            .formParam("ResourceType", "VPC")
            .formParam("ResourceId.1", "vpc-default")
            .formParam("TrafficType", "ACCEPT")
            .formParam("LogDestinationType", "cloud-watch-logs")
            .formParam("LogGroupName", "VpcFlowLogsIntegrationTest")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("CreateFlowLogsResponse.flowLogIdSet.item", startsWith("fl-"))
            .extract().path("CreateFlowLogsResponse.flowLogIdSet.item");
    }

    @Test
    @Order(6)
    void cloudWatchLogsReceiveFlowLogRecords() {
        given()
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("X-Amz-Target", "Logs_20140328.FilterLogEvents")
            .body("""
                    {
                      "logGroupName": "VpcFlowLogsIntegrationTest",
                      "limit": 10
                    }
                    """)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("events.size()", greaterThanOrEqualTo(1))
            .body("events[0].message", notNullValue());
    }

    @Test
    @Order(7)
    void deleteFlowLogs() {
        given()
            .formParam("Action", "DeleteFlowLogs")
            .formParam("FlowLogId.1", s3FlowLogId)
            .formParam("FlowLogId.2", cwFlowLogId)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DeleteFlowLogsResponse.unsuccessful.item.size()", equalTo(0));

        given()
            .formParam("Action", "DescribeFlowLogs")
            .formParam("FlowLogId.1", s3FlowLogId)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeFlowLogsResponse.flowLogSet.item.size()", equalTo(0));
    }

    @Test
    @Order(8)
    void createFlowLogRejectsMissingResource() {
        given()
            .formParam("Action", "CreateFlowLogs")
            .formParam("ResourceType", "VPC")
            .formParam("ResourceId.1", "vpc-does-not-exist")
            .formParam("LogDestinationType", "s3")
            .formParam("LogDestination", "arn:aws:s3:::flow-logs-int-bucket/")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("CreateFlowLogsResponse.flowLogIdSet.item.size()", equalTo(0))
            .body("CreateFlowLogsResponse.unsuccessful.item[0].resourceId", equalTo("vpc-does-not-exist"));
    }
}
