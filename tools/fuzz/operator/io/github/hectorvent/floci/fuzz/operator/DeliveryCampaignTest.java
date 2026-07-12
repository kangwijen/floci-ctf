package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

/**
 * Inter-service delivery smoke campaigns against live CTF Compose.
 *
 * <p>Drives control-plane unsigned calls that would otherwise open SNS/EventBridge/Pipes
 * delivery paths without IAM. Full signed delivery scenarios belong in src/test regressions
 * once a finding is minimized.
 */
class DeliveryCampaignTest {

    private DifferentialHttpOracle oracle;

    @BeforeEach
    void setUp() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        var maybe = DifferentialHttpOracle.fromEnv();
        Assumptions.assumeTrue(maybe.isPresent(), "Set AWS_ENDPOINT_URL for delivery campaigns");
        oracle = maybe.get();
    }

    @Test
    void unsignedCreateEventBusDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "AWSEvents.CreateEventBus"),
                "{\"Name\":\"fuzz-bus\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Delivery.events.createBus",
                    "CreateEventBus",
                    "unsigned CreateEventBus succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedPutRuleDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "AWSEvents.PutRule"),
                "{\"Name\":\"fuzz-rule\",\"EventPattern\":\"{}\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Delivery.events.putRule",
                    "PutRule",
                    "unsigned PutRule succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedCreatePipeDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/v1/pipes",
                Map.of("Content-Type", "application/json"),
                "{\"Name\":\"fuzz-pipe\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Delivery.pipes.create",
                    "CreatePipe",
                    "unsigned CreatePipe succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedCreateTopicDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of("Content-Type", "application/x-www-form-urlencoded"),
                "Action=CreateTopic&Name=fuzz-topic&Version=2010-03-31");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Delivery.sns.createTopic",
                    "CreateTopic",
                    "unsigned CreateTopic succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedStartReplayDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "AWSEvents.StartReplay"),
                "{\"ReplayName\":\"fuzz-replay\",\"EventSourceArn\":\"arn:aws:events:us-east-1:123456789012:archive/a\","
                        + "\"Destination\":{\"Arn\":\"arn:aws:events:us-east-1:123456789012:event-bus/default\"},"
                        + "\"EventStartTime\":0,\"EventEndTime\":1}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Delivery.events.replay",
                    "StartReplay",
                    "unsigned StartReplay succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedCreateEventSourceMappingDenied() throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/2015-03-31/event-source-mappings",
                Map.of("Content-Type", "application/json"),
                "{\"FunctionName\":\"fn\",\"EventSourceArn\":\"arn:aws:sqs:us-east-1:123456789012:q\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Delivery.lambda.esm",
                    "CreateEventSourceMapping",
                    "unsigned CreateEventSourceMapping succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }
}
