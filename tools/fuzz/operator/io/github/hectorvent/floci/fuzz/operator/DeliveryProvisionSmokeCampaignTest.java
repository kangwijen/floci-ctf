package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * Unsigned deny smoke for delivery-path provisioning APIs (Scheduler, EventBridge targets,
 * Logs subscriptions, CloudTrail, Config, Firehose, tagging).
 *
 * <p>Complements {@link DeliveryCampaignTest}. Skipped when {@code fuzz.operator.skip} is true
 * or {@code AWS_ENDPOINT_URL} is unset.
 */
class DeliveryProvisionSmokeCampaignTest {

    private DifferentialHttpOracle oracle;

    @BeforeEach
    void setUp() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        var maybe = DifferentialHttpOracle.fromEnv();
        Assumptions.assumeTrue(maybe.isPresent(), "Set AWS_ENDPOINT_URL for delivery provision smoke");
        oracle = maybe.get();
    }

    @Test
    void unsignedCreateScheduleDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/schedules/fuzz-sched",
                Map.of("Content-Type", "application/json"),
                "{\"ScheduleExpression\":\"rate(1 hour)\",\"FlexibleTimeWindow\":{\"Mode\":\"OFF\"},"
                        + "\"Target\":{\"Arn\":\"arn:aws:sqs:us-east-1:000000000000:q\","
                        + "\"RoleArn\":\"arn:aws:iam::000000000000:role/fuzz\"}}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.scheduler.create",
                    "CreateSchedule",
                    "unsigned CreateSchedule succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedPutTargetsDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "AWSEvents.PutTargets"),
                "{\"Rule\":\"fuzz-rule\",\"Targets\":[{\"Id\":\"1\","
                        + "\"Arn\":\"arn:aws:sqs:us-east-1:000000000000:q\"}]}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.events.putTargets",
                    "PutTargets",
                    "unsigned PutTargets succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedPutSubscriptionFilterDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "Logs_20140328.PutSubscriptionFilter"),
                "{\"logGroupName\":\"/aws/fuzz\",\"filterName\":\"f\","
                        + "\"filterPattern\":\"\",\"destinationArn\":"
                        + "\"arn:aws:lambda:us-east-1:000000000000:function:fn\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.logs.subscription",
                    "PutSubscriptionFilter",
                    "unsigned PutSubscriptionFilter succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedCreateTrailDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target",
                        "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.CreateTrail"),
                "{\"Name\":\"fuzz-trail\",\"S3BucketName\":\"fuzz-bucket\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.cloudtrail.createTrail",
                    "CreateTrail",
                    "unsigned CreateTrail succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedPutDeliveryChannelDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "StarlingDoveService.PutDeliveryChannel"),
                "{\"DeliveryChannel\":{\"name\":\"fuzz-channel\",\"s3BucketName\":\"fuzz-bucket\"}}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.config.putDeliveryChannel",
                    "PutDeliveryChannel",
                    "unsigned PutDeliveryChannel succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedCreateDeliveryStreamDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "Firehose_20150804.CreateDeliveryStream"),
                "{\"DeliveryStreamName\":\"fuzz-stream\",\"DeliveryStreamType\":\"DirectPut\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.firehose.createDeliveryStream",
                    "CreateDeliveryStream",
                    "unsigned CreateDeliveryStream succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedTagResourcesDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "ResourceGroupsTaggingAPI_20170126.TagResources"),
                "{\"ResourceARNList\":[\"arn:aws:s3:::fuzz-bucket\"],"
                        + "\"Tags\":{\"env\":\"fuzz\"}}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "DeliveryProvision.tagging.tagResources",
                    "TagResources",
                    "unsigned TagResources succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }
}
