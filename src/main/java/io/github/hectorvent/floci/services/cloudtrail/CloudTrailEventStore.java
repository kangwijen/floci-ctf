package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEventResource;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

@ApplicationScoped
public class CloudTrailEventStore {
    private static final int DEFAULT_MAX_RESULTS = 50;
    private static final int MAX_MAX_RESULTS = 50;
    private static final Set<String> SUPPORTED_LOOKUP_KEYS = Set.of(
            "EventName", "Username", "ResourceName", "EventSource", "ReadOnly");

    private final StorageBackend<String, CloudTrailEvent> eventStore;
    private final AtomicLong sequenceCounter = new AtomicLong();

    @Inject
    public CloudTrailEventStore(StorageFactory storageFactory) {
        this.eventStore = storageFactory.create("cloudtrail", "cloudtrail-events.json",
                new TypeReference<Map<String, CloudTrailEvent>>() {});
    }

    CloudTrailEventStore(StorageBackend<String, CloudTrailEvent> eventStore) {
        this.eventStore = eventStore;
    }

    public void store(CloudTrailEvent event) {
        eventStore.put(storageKey(event.getRegion(), event.getEventId()), event);
    }

    void clear() {
        eventStore.clear();
        sequenceCounter.set(0);
    }

    public void indexRecordedEvent(String region,
                                   Map<String, Object> event,
                                   CloudTrailEventRecorder recorder) {
        CloudTrailEvent indexed = new CloudTrailEvent();
        indexed.setRegion(region);
        indexed.setEventId(recorder.eventId(event));
        indexed.setEventName(recorder.eventName(event));
        indexed.setEventSource(recorder.eventSource(event));
        indexed.setEventTime(recorder.eventTime(event));
        indexed.setSequence(sequenceCounter.incrementAndGet());
        indexed.setUsername(recorder.username(event));
        indexed.setReadOnly(recorder.readOnly(event));
        indexed.setFullEventJson(recorder.toJson(event));
        indexed.setResources(extractResources(event));
        if (!indexed.getResources().isEmpty()) {
            CloudTrailEventResource primary = indexed.getResources().get(0);
            indexed.setResourceArn(primary.getResourceName());
            indexed.setResourceType(primary.getResourceType());
        }
        store(indexed);
    }

    @SuppressWarnings("unchecked")
    private static List<CloudTrailEventResource> extractResources(Map<String, Object> event) {
        Object resources = event.get("resources");
        if (!(resources instanceof List<?> resourceList)) {
            return List.of();
        }
        List<CloudTrailEventResource> parsed = new ArrayList<>();
        for (Object item : resourceList) {
            if (!(item instanceof Map<?, ?> map)) {
                continue;
            }
            String arn = stringValue(map.get("ARN"));
            if (arn == null) {
                arn = stringValue(map.get("ResourceName"));
            }
            String type = stringValue(map.get("type"));
            if (type == null) {
                type = stringValue(map.get("ResourceType"));
            }
            if (arn != null || type != null) {
                parsed.add(new CloudTrailEventResource(arn, type));
            }
        }
        return parsed;
    }

    private static String stringValue(Object value) {
        return value == null ? null : value.toString();
    }

    public LookupEventsResult lookup(String region,
                                     Instant startTime,
                                     Instant endTime,
                                     List<LookupAttribute> lookupAttributes,
                                     Integer maxResults,
                                     String nextToken) {
        validateTimeRange(startTime, endTime);
        validateLookupAttributes(lookupAttributes);
        int limit = resolveMaxResults(maxResults);
        int offset = decodeNextToken(nextToken);

        List<CloudTrailEvent> matched = eventStore.scan(key -> key.startsWith(region + ":")).stream()
                .filter(event -> matchesTimeRange(event, startTime, endTime))
                .filter(event -> matchesLookupAttributes(event, lookupAttributes))
                .sorted(Comparator
                        .comparing(CloudTrailEvent::getEventTime,
                                Comparator.nullsLast(Comparator.reverseOrder()))
                        .thenComparing(CloudTrailEvent::getSequence, Comparator.reverseOrder()))
                .toList();

        if (offset < 0 || offset > matched.size()) {
            throw new AwsException("InvalidNextTokenException",
                    "The token provided is invalid or has expired.", 400);
        }

        int end = Math.min(matched.size(), offset + limit);
        List<CloudTrailEvent> page = matched.subList(offset, end);
        String token = end < matched.size() ? encodeNextToken(end) : null;
        return new LookupEventsResult(page, token);
    }

    private static void validateTimeRange(Instant startTime, Instant endTime) {
        if (startTime != null && endTime != null && startTime.isAfter(endTime)) {
            throw new AwsException("InvalidTimeRangeException",
                    "The specified start time is after the end time.", 400);
        }
    }

    private static void validateLookupAttributes(List<LookupAttribute> lookupAttributes) {
        if (lookupAttributes == null || lookupAttributes.isEmpty()) {
            return;
        }
        if (lookupAttributes.size() > 1) {
            throw new AwsException("InvalidLookupAttributesException",
                    "LookupAttributes can contain only one item.", 400);
        }
        LookupAttribute attribute = lookupAttributes.get(0);
        if (attribute.attributeKey() == null || attribute.attributeKey().isBlank()) {
            throw new AwsException("InvalidLookupAttributesException",
                    "An AttributeKey is required for each lookup attribute.", 400);
        }
        if (!SUPPORTED_LOOKUP_KEYS.contains(attribute.attributeKey())) {
            throw new AwsException("InvalidLookupAttributesException",
                    "The lookup attribute key is not valid.", 400);
        }
        if (attribute.attributeValue() == null || attribute.attributeValue().isBlank()) {
            throw new AwsException("InvalidLookupAttributesException",
                    "An AttributeValue is required for each lookup attribute.", 400);
        }
        if (attribute.attributeValue().length() > 2000) {
            throw new AwsException("InvalidLookupAttributesException",
                    "The lookup attribute value is too long.", 400);
        }
        if ("ReadOnly".equals(attribute.attributeKey())) {
            String normalized = attribute.attributeValue().toLowerCase(Locale.ROOT);
            if (!"true".equals(normalized) && !"false".equals(normalized)) {
                throw new AwsException("InvalidLookupAttributesException",
                        "ReadOnly lookup attribute value must be true or false.", 400);
            }
        }
    }

    private static int resolveMaxResults(Integer maxResults) {
        if (maxResults == null) {
            return DEFAULT_MAX_RESULTS;
        }
        if (maxResults < 1 || maxResults > MAX_MAX_RESULTS) {
            throw new AwsException("InvalidMaxResultsException",
                    "MaxResults must be between 1 and 50.", 400);
        }
        return maxResults;
    }

    private static boolean matchesTimeRange(CloudTrailEvent event, Instant startTime, Instant endTime) {
        Instant eventTime = event.getEventTime();
        if (eventTime == null) {
            return false;
        }
        if (startTime != null && eventTime.isBefore(startTime)) {
            return false;
        }
        return endTime == null || !eventTime.isAfter(endTime);
    }

    private static boolean matchesLookupAttributes(CloudTrailEvent event, List<LookupAttribute> lookupAttributes) {
        if (lookupAttributes == null || lookupAttributes.isEmpty()) {
            return true;
        }
        LookupAttribute attribute = lookupAttributes.get(0);
        return switch (attribute.attributeKey()) {
            case "EventName" -> attribute.attributeValue().equals(event.getEventName());
            case "Username" -> attribute.attributeValue().equals(event.getUsername());
            case "EventSource" -> attribute.attributeValue().equals(event.getEventSource());
            case "ReadOnly" -> Boolean.parseBoolean(attribute.attributeValue()) == event.isReadOnly();
            case "ResourceName" -> matchesResourceName(event, attribute.attributeValue());
            default -> false;
        };
    }

    private static boolean matchesResourceName(CloudTrailEvent event, String resourceName) {
        if (resourceName.equals(event.getResourceArn())) {
            return true;
        }
        if (event.getResources() != null) {
            for (CloudTrailEventResource resource : event.getResources()) {
                if (resourceName.equals(resource.getResourceName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String storageKey(String region, String eventId) {
        return region + ":" + eventId;
    }

    private static String encodeNextToken(int offset) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(Integer.toString(offset).getBytes(StandardCharsets.UTF_8));
    }

    private static int decodeNextToken(String nextToken) {
        if (nextToken == null || nextToken.isBlank()) {
            return 0;
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(nextToken);
            return Integer.parseInt(new String(decoded, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException e) {
            return -1;
        }
    }

    public record LookupAttribute(String attributeKey, String attributeValue) {
    }

    public record LookupEventsResult(List<CloudTrailEvent> events, String nextToken) {
        public LookupEventsResult {
            events = events == null ? List.of() : List.copyOf(events);
        }
    }
}
