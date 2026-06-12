package io.github.hectorvent.floci.services.cloudwatch.logs;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.cloudwatch.logs.model.LogEvent;
import io.github.hectorvent.floci.services.cloudwatch.logs.model.SubscriptionFilter;
import io.github.hectorvent.floci.services.firehose.FirehoseService;
import io.github.hectorvent.floci.services.firehose.model.Record;
import io.github.hectorvent.floci.services.kinesis.KinesisService;
import io.github.hectorvent.floci.services.lambda.LambdaArnUtils;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.lambda.model.InvocationType;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

@ApplicationScoped
public class CloudWatchLogsSubscriptionDispatcher {

    private static final Logger LOG = Logger.getLogger(CloudWatchLogsSubscriptionDispatcher.class);

    private final ObjectMapper objectMapper;
    private final RegionResolver regionResolver;
    private final FirehoseService firehoseService;
    private final KinesisService kinesisService;
    private final LambdaService lambdaService;
    private final InProcessCloudTrailRecorder cloudTrailRecorder;

    @Inject
    public CloudWatchLogsSubscriptionDispatcher(ObjectMapper objectMapper,
                                                RegionResolver regionResolver,
                                                FirehoseService firehoseService,
                                                KinesisService kinesisService,
                                                LambdaService lambdaService,
                                                InProcessCloudTrailRecorder cloudTrailRecorder) {
        this.objectMapper = objectMapper;
        this.regionResolver = regionResolver;
        this.firehoseService = firehoseService;
        this.kinesisService = kinesisService;
        this.lambdaService = lambdaService;
        this.cloudTrailRecorder = cloudTrailRecorder;
    }

    public void dispatch(String logGroupName,
                         String logStreamName,
                         List<LogEvent> events,
                         List<SubscriptionFilter> filters,
                         String region) {
        if (filters == null || filters.isEmpty() || events == null || events.isEmpty()) {
            return;
        }

        for (SubscriptionFilter filter : filters) {
            List<LogEvent> matched = new ArrayList<>();
            for (LogEvent event : events) {
                if (matchesFilterPattern(filter.getFilterPattern(), event.getMessage())) {
                    matched.add(event);
                }
            }
            if (matched.isEmpty()) {
                continue;
            }

            try {
                byte[] payload = buildSubscriptionMessage(
                        logGroupName, logStreamName, filter.getFilterName(), matched, region);
                deliver(filter.getDestinationArn(), payload, logStreamName, region);
            } catch (Exception e) {
                LOG.warnv("Failed to deliver subscription filter {0} for log group {1}: {2}",
                        filter.getFilterName(), logGroupName, e.getMessage());
            }
        }
    }

    static boolean matchesFilterPattern(String filterPattern, String message) {
        if (filterPattern == null || filterPattern.isBlank() || "*".equals(filterPattern)) {
            return true;
        }
        return message != null && message.contains(filterPattern);
    }

    private byte[] buildSubscriptionMessage(String logGroupName,
                                            String logStreamName,
                                            String filterName,
                                            List<LogEvent> events,
                                            String region) throws Exception {
        ObjectNode root = objectMapper.createObjectNode();
        root.put("messageType", "DATA_MESSAGE");
        root.put("owner", regionResolver.getAccountId());
        root.put("logGroup", logGroupName);
        root.put("logStream", logStreamName);
        ArrayNode filterNames = objectMapper.createArrayNode();
        filterNames.add(filterName);
        root.set("subscriptionFilters", filterNames);

        ArrayNode logEvents = objectMapper.createArrayNode();
        for (LogEvent event : events) {
            ObjectNode node = objectMapper.createObjectNode();
            node.put("id", event.getEventId());
            node.put("timestamp", event.getTimestamp());
            node.put("message", event.getMessage());
            logEvents.add(node);
        }
        root.set("logEvents", logEvents);

        return objectMapper.writeValueAsBytes(root);
    }

    private void deliver(String destinationArn, byte[] jsonPayload, String partitionKey, String region)
            throws Exception {
        AwsArnUtils.Arn arn = AwsArnUtils.parse(destinationArn);
        String destRegion = arn.region().isEmpty() ? region : arn.region();

        switch (arn.service()) {
            case "lambda" -> deliverToLambda(destinationArn, jsonPayload, destRegion);
            case "firehose" -> deliverToFirehose(arn, gzip(jsonPayload));
            case "kinesis" -> deliverToKinesis(arn, gzip(jsonPayload), partitionKey, destRegion);
            default -> LOG.warnv("Unsupported subscription filter destination service: {0}", arn.service());
        }
    }

    private void deliverToLambda(String destinationArn, byte[] jsonPayload, String region) {
        LambdaArnUtils.ResolvedFunctionRef ref = LambdaArnUtils.resolve(destinationArn);
        String functionName = ref.qualifier() != null
                ? ref.name() + ":" + ref.qualifier()
                : ref.name();
        try {
            lambdaService.getFunction(region, functionName);
        } catch (AwsException e) {
            if ("ResourceNotFoundException".equals(e.getErrorCode())) {
                LOG.debugv("Skipping subscription delivery; Lambda function not found: {0}", functionName);
                return;
            }
            throw e;
        }
        lambdaService.invoke(region, functionName, jsonPayload, InvocationType.Event);
        cloudTrailRecorder.recordAwsServiceEvent(region, "lambda.amazonaws.com", "Invoke",
                "logs.amazonaws.com", Map.of("functionName", functionName));
    }

    private void deliverToFirehose(AwsArnUtils.Arn arn, byte[] data) {
        String streamName = extractNamedResource(arn.resource(), "deliverystream/");
        firehoseService.putRecord(streamName, new Record(data));
        String destRegion = arn.region().isEmpty() ? regionResolver.resolveRegion(null) : arn.region();
        cloudTrailRecorder.recordAwsServiceEvent(destRegion, "firehose.amazonaws.com", "PutRecord",
                "logs.amazonaws.com", Map.of("deliveryStreamName", streamName));
    }

    private void deliverToKinesis(AwsArnUtils.Arn arn, byte[] data, String partitionKey, String region) {
        String streamName = extractNamedResource(arn.resource(), "stream/");
        kinesisService.putRecord(streamName, data, partitionKey, region);
        cloudTrailRecorder.recordAwsServiceEvent(region, "kinesis.amazonaws.com", "PutRecord",
                "logs.amazonaws.com", Map.of("streamName", streamName));
    }

    private static String extractNamedResource(String resource, String prefix) {
        if (resource.startsWith(prefix)) {
            return resource.substring(prefix.length());
        }
        int idx = resource.lastIndexOf('/');
        return idx >= 0 ? resource.substring(idx + 1) : resource;
    }

    private static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(baos)) {
            gzip.write(data);
        }
        return baos.toByteArray();
    }
}
