package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEventResource;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailTrail;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.s3.S3Service;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;

@ApplicationScoped
public class CloudTrailDeliveryService {

    private static final Logger LOG = Logger.getLogger(CloudTrailDeliveryService.class);
    private static final int DEFAULT_BUFFER_SIZE = 10;
    private static final DateTimeFormatter DAY_PATH =
            DateTimeFormatter.ofPattern("yyyy/MM/dd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter FILE_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private final S3Service s3Service;
    private final RegionResolver regionResolver;
    private final ObjectMapper mapper;
    private final CloudTrailEventStore eventStore;
    private final InProcessTargetAuthorizer targetAuthorizer;
    private final ConcurrentHashMap<String, List<Map<String, Object>>> buffers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, TrailDeliveryContext> trailContexts = new ConcurrentHashMap<>();
    private volatile int bufferSize = DEFAULT_BUFFER_SIZE;

    @Inject
    public CloudTrailDeliveryService(S3Service s3Service,
                                     RegionResolver regionResolver,
                                     ObjectMapper mapper,
                                     CloudTrailEventStore eventStore,
                                     InProcessTargetAuthorizer targetAuthorizer) {
        this.s3Service = s3Service;
        this.regionResolver = regionResolver;
        this.mapper = mapper;
        this.eventStore = eventStore;
        this.targetAuthorizer = targetAuthorizer;
    }

    /**
     * Stores a synthetic event for LookupEvents tests without S3 delivery.
     */
    public void recordEvent(String region,
                            String eventName,
                            String eventSource,
                            String username,
                            String resourceArn,
                            String resourceType,
                            boolean readOnly,
                            Instant eventTime) {
        String eventId = UUID.randomUUID().toString();
        Map<String, Object> fullEvent = new LinkedHashMap<>();
        fullEvent.put("eventVersion", "1.08");
        fullEvent.put("eventID", eventId);
        fullEvent.put("eventName", eventName);
        fullEvent.put("eventSource", eventSource);
        fullEvent.put("awsRegion", region);
        fullEvent.put("eventTime", CloudTrailEventRecorder.formatEventTime(eventTime));
        fullEvent.put("readOnly", readOnly);
        if (username != null) {
            Map<String, Object> identity = new LinkedHashMap<>();
            identity.put("type", "IAMUser");
            identity.put("userName", username);
            identity.put("arn", "arn:aws:iam::" + regionResolver.getAccountId() + ":user/" + username);
            fullEvent.put("userIdentity", identity);
        }
        if (resourceArn != null) {
            fullEvent.put("resources", List.of(Map.of(
                    "ARN", resourceArn,
                    "type", resourceType == null ? "AWS::Resource" : resourceType)));
        }

        CloudTrailEvent indexed = new CloudTrailEvent();
        indexed.setEventId(eventId);
        indexed.setRegion(region);
        indexed.setEventName(eventName);
        indexed.setEventSource(eventSource);
        indexed.setEventTime(eventTime);
        indexed.setUsername(username);
        indexed.setReadOnly(readOnly);
        indexed.setResourceArn(resourceArn);
        indexed.setResourceType(resourceType);
        if (resourceArn != null) {
            indexed.setResources(List.of(new CloudTrailEventResource(resourceArn, resourceType)));
        }
        try {
            indexed.setFullEventJson(mapper.writeValueAsString(fullEvent));
        } catch (Exception e) {
            indexed.setFullEventJson("{\"eventName\":\"" + eventName + "\"}");
        }
        eventStore.store(indexed);
    }

    public void setBufferSizeForTests(int bufferSize) {
        this.bufferSize = Math.max(1, bufferSize);
    }

    public void bufferEvent(CloudTrailTrail trail, String region, Map<String, Object> event) {
        if (trail == null || trail.getS3BucketName() == null || trail.getS3BucketName().isBlank()) {
            return;
        }
        String bufferKey = trail.getTrailArn();
        trailContexts.put(bufferKey, new TrailDeliveryContext(trail, region));
        List<Map<String, Object>> buffer = buffers.computeIfAbsent(bufferKey, ignored -> new ArrayList<>());
        List<Map<String, Object>> toFlush = null;
        synchronized (buffer) {
            buffer.add(event);
            if (buffer.size() >= bufferSize) {
                toFlush = new ArrayList<>(buffer);
                buffer.clear();
            }
        }
        if (toFlush != null) {
            deliver(trail, region, toFlush);
        }
    }

    public void flushAll() {
        for (var entry : buffers.entrySet()) {
            TrailDeliveryContext context = trailContexts.get(entry.getKey());
            if (context == null) {
                continue;
            }
            List<Map<String, Object>> toFlush;
            synchronized (entry.getValue()) {
                if (entry.getValue().isEmpty()) {
                    continue;
                }
                toFlush = new ArrayList<>(entry.getValue());
                entry.getValue().clear();
            }
            deliver(context.trail(), context.region(), toFlush);
        }
    }

    @PreDestroy
    void shutdown() {
        flushAll();
    }

    private void deliver(CloudTrailTrail trail, String region, List<Map<String, Object>> events) {
        if (events.isEmpty()) {
            return;
        }
        String accountId = regionResolver.getAccountId();
        Instant now = Instant.now();
        String dayPath = DAY_PATH.format(now);
        String objectKey = "AWSLogs/" + accountId + "/CloudTrail/" + region + "/" + dayPath + "/"
                + accountId + "_CloudTrail_" + region + "_" + FILE_TIMESTAMP.format(now) + ".json.gz";
        try {
            byte[] payload = gzipJsonArray(events);
            targetAuthorizer.authorizeServiceS3Put(
                    InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE, trail.getS3BucketName(), objectKey, region);
            s3Service.putObject(trail.getS3BucketName(), objectKey, payload, "application/json", Map.of());
            LOG.debugv("Delivered {0} CloudTrail events to s3://{1}/{2}",
                    events.size(), trail.getS3BucketName(), objectKey);
        } catch (Exception e) {
            LOG.warnv(e, "Failed to deliver CloudTrail events to s3://{0}", trail.getS3BucketName());
        }
    }

    private byte[] gzipJsonArray(List<Map<String, Object>> events) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
            mapper.writeValue(gzip, events);
        }
        return bytes.toByteArray();
    }

    private record TrailDeliveryContext(CloudTrailTrail trail, String region) {
    }
}
