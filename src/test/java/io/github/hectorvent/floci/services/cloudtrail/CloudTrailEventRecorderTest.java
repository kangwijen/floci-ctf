package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    @Test
    void buildInProcessEvent_normalizesSqsJsonBodyQueueUrl() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        when(config.defaultAccountId()).thenReturn("000000000000");
        CloudTrailEventRecorder recorder = new CloudTrailEventRecorder(
                new ObjectMapper(),
                mock(AccountResolver.class),
                mock(IamService.class),
                mock(ResourceArnBuilder.class),
                config,
                mock(Instance.class));

        String queueUrl = "http://localhost:4566/000000000000/inprocess-queue";
        Map<String, Object> requestParameters = new LinkedHashMap<>();
        requestParameters.put("QueueUrl", queueUrl);
        requestParameters.put("MessageBody", "payload");

        Map<String, Object> event = recorder.buildInProcessEvent(InProcessAuditContext.builder()
                .region("us-east-1")
                .eventName("SendMessage")
                .credentialScope("sqs")
                .requestParameters(requestParameters)
                .invokedBy("states.amazonaws.com")
                .executionRoleArn("arn:aws:iam::000000000000:role/SfnRole")
                .managementEvent(false)
                .eventCategory("Data")
                .build());

        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) event.get("requestParameters");
        assertEquals(queueUrl, params.get("queueUrl"));
        assertEquals("payload", params.get("messageBody"));
        assertFalse(params.containsKey("QueueUrl"));
        assertFalse(params.containsKey("MessageBody"));
        assertEquals("Data", event.get("eventCategory"));
    }

    @Test
    void toEventName_mapsListTypeTwoToListObjectsV2() {
        jakarta.ws.rs.container.ContainerRequestContext request = org.mockito.Mockito.mock(
                jakarta.ws.rs.container.ContainerRequestContext.class);
        jakarta.ws.rs.core.UriInfo uriInfo = org.mockito.Mockito.mock(jakarta.ws.rs.core.UriInfo.class);
        jakarta.ws.rs.core.MultivaluedMap<String, String> listV2Query = new jakarta.ws.rs.core.MultivaluedHashMap<>();
        listV2Query.add("list-type", "2");
        org.mockito.Mockito.when(request.getUriInfo()).thenReturn(uriInfo);
        org.mockito.Mockito.when(uriInfo.getQueryParameters()).thenReturn(listV2Query);

        assertEquals("ListObjectsV2",
                CloudTrailEventRecorder.toEventName("s3:ListBucket", request, "s3"));

        jakarta.ws.rs.core.MultivaluedMap<String, String> v1Query = new jakarta.ws.rs.core.MultivaluedHashMap<>();
        org.mockito.Mockito.when(uriInfo.getQueryParameters()).thenReturn(v1Query);
        assertEquals("ListBucket",
                CloudTrailEventRecorder.toEventName("s3:ListBucket", request, "s3"));
    }
}
