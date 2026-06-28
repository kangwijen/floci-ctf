package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.core.common.AwsException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@ApplicationScoped
public class CloudTrailEventInjectionService {

    private static final String DEFAULT_EVENT_VERSION = "1.08";

    private final CloudTrailService cloudTrailService;
    private final CloudTrailEventRecorder eventRecorder;

    @Inject
    public CloudTrailEventInjectionService(CloudTrailService cloudTrailService,
                                           CloudTrailEventRecorder eventRecorder) {
        this.cloudTrailService = cloudTrailService;
        this.eventRecorder = eventRecorder;
    }

    public InjectedEventResult injectEvent(String region,
                                           Map<String, Object> event,
                                           boolean preserveEventTime,
                                           boolean deliverToTrails) {
        Map<String, Object> normalized = normalizeEvent(region, event, preserveEventTime);
        cloudTrailService.recordInjectedEvent(region, normalized, preserveEventTime, deliverToTrails);
        return new InjectedEventResult(
                eventRecorder.eventId(normalized),
                CloudTrailEventRecorder.formatEventTime(eventRecorder.eventTime(normalized)));
    }

    public List<InjectedEventResult> injectBatch(String region,
                                                 List<Map<String, Object>> events,
                                                 boolean preserveEventTime,
                                                 boolean deliverToTrails) {
        if (events == null || events.isEmpty()) {
            throw new AwsException("ValidationException", "At least one event is required.", 400);
        }
        List<InjectedEventResult> results = new ArrayList<>(events.size());
        for (Map<String, Object> event : events) {
            results.add(injectEvent(region, event, preserveEventTime, deliverToTrails));
        }
        return results;
    }

    private Map<String, Object> normalizeEvent(String region,
                                               Map<String, Object> event,
                                               boolean preserveEventTime) {
        if (event == null || event.isEmpty()) {
            throw new AwsException("ValidationException", "Event body is required.", 400);
        }
        Map<String, Object> normalized = new LinkedHashMap<>(event);
        requireNonBlank(normalized, "eventName");
        requireNonBlank(normalized, "eventSource");
        if (preserveEventTime) {
            requireNonBlank(normalized, "eventTime");
            try {
                eventRecorder.eventTime(normalized);
            } catch (RuntimeException e) {
                throw new AwsException("ValidationException", "eventTime is invalid.", 400);
            }
        }
        normalized.putIfAbsent("eventVersion", DEFAULT_EVENT_VERSION);
        normalized.putIfAbsent("awsRegion", region);
        Object eventId = normalized.get("eventID");
        if (eventId == null || eventId.toString().isBlank()) {
            normalized.put("eventID", UUID.randomUUID().toString());
        }
        return normalized;
    }

    private static void requireNonBlank(Map<String, Object> event, String field) {
        Object value = event.get(field);
        if (value == null || value.toString().isBlank()) {
            throw new AwsException("ValidationException", field + " is required.", 400);
        }
    }

    public record InjectedEventResult(String eventId, String eventTime) {
    }
}
