package io.github.hectorvent.floci.services.cloudtrail;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudTrailEventRecorderTest {

    @Test
    void formatEventTime_usesUtcWithMilliseconds() {
        Instant instant = Instant.parse("2026-06-15T12:34:56.789Z");

        String formatted = CloudTrailEventRecorder.formatEventTime(instant);

        assertEquals("2026-06-15T12:34:56.789Z", formatted);
        assertTrue(formatted.matches("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z"));
    }

    @Test
    void isDataEvent_classifiesS3ObjectAndSqsDataPlane() {
        assertTrue(CloudTrailEventRecorder.isDataEvent("s3.amazonaws.com", "PutObject", null));
        assertTrue(CloudTrailEventRecorder.isDataEvent("sqs.amazonaws.com", "SendMessage", null));
        assertFalse(CloudTrailEventRecorder.isDataEvent("sqs.amazonaws.com", "PurgeQueue", null));
        assertFalse(CloudTrailEventRecorder.isDataEvent("sts.amazonaws.com", "AssumeRole", null));
    }

    @Test
    void isReadOnly_matchesAssumeRoleAndReceiveMessage() {
        assertTrue(CloudTrailEventRecorder.isReadOnly("AssumeRole"));
        assertTrue(CloudTrailEventRecorder.isReadOnly("ReceiveMessage"));
        assertFalse(CloudTrailEventRecorder.isReadOnly("SendMessage"));
    }

    @Test
    void cloudTrailResourceType_mapsS3ObjectAndSqsQueue() {
        assertEquals("AWS::S3::Object",
                CloudTrailEventRecorder.cloudTrailResourceType(
                        "s3", "PutObject", "arn:aws:s3:::bucket/key.txt"));
        assertEquals("AWS::SQS::Queue",
                CloudTrailEventRecorder.cloudTrailResourceType(
                        "sqs", "SendMessage", "arn:aws:sqs:us-east-1:123:queue"));
    }
}
