package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailAdvancedEventSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailAdvancedFieldSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailDataResource;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEventResource;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEventSelector;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailTrail;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class CloudTrailJsonHandler {
    private final CloudTrailService service;
    private final ObjectMapper mapper;

    @Inject
    public CloudTrailJsonHandler(CloudTrailService service, ObjectMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    public Response handle(String action, JsonNode request, String region) {
        return switch (action) {
            case "CreateTrail" -> createTrail(request, region);
            case "UpdateTrail" -> updateTrail(request, region);
            case "DescribeTrails" -> describeTrails(request, region);
            case "StartLogging" -> startLogging(request, region);
            case "StopLogging" -> stopLogging(request, region);
            case "DeleteTrail" -> deleteTrail(request, region);
            case "GetTrailStatus" -> getTrailStatus(request, region);
            case "PutEventSelectors" -> putEventSelectors(request, region);
            case "GetEventSelectors" -> getEventSelectors(request, region);
            case "LookupEvents" -> lookupEvents(request, region);
            default -> throw new AwsException("UnsupportedOperation",
                    "Operation " + action + " is not supported.", 400);
        };
    }

    private Response createTrail(JsonNode request, String region) {
        CloudTrailTrail trail = service.createTrail(
                region,
                request.path("Name").asText(null),
                request.path("S3BucketName").asText(null),
                request.path("IncludeGlobalServiceEvents").asBoolean(false),
                request.path("IsMultiRegionTrail").asBoolean(false),
                request.path("IsOrganizationTrail").asBoolean(false),
                parseTags(request.path("TagsList")));
        return Response.ok(trailNode(trail)).build();
    }

    private Response updateTrail(JsonNode request, String region) {
        CloudTrailTrail trail = service.updateTrail(
                region,
                request.path("Name").asText(null),
                request.path("S3BucketName").asText(null),
                optionalBoolean(request, "IncludeGlobalServiceEvents"),
                optionalBoolean(request, "IsMultiRegionTrail"));
        return Response.ok(trailNode(trail)).build();
    }

    private Response describeTrails(JsonNode request, String region) {
        List<String> names = stringList(request.path("trailNameList"));
        ObjectNode response = mapper.createObjectNode();
        ArrayNode trails = response.putArray("trailList");
        for (CloudTrailTrail trail : service.describeTrails(region, names)) {
            trails.add(trailNode(trail));
        }
        return Response.ok(response).build();
    }

    private Response startLogging(JsonNode request, String region) {
        service.startLogging(region, request.path("Name").asText(null));
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response stopLogging(JsonNode request, String region) {
        service.stopLogging(region, request.path("Name").asText(null));
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response deleteTrail(JsonNode request, String region) {
        service.deleteTrail(region, request.path("Name").asText(null));
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response getTrailStatus(JsonNode request, String region) {
        CloudTrailTrail trail = service.requireTrail(region, request.path("Name").asText(null));
        ObjectNode response = mapper.createObjectNode();
        response.put("IsLogging", trail.isLogging());
        if (trail.getUpdated() != null) {
            response.put("LatestDeliveryTime", trail.getUpdated().toEpochMilli() / 1000.0);
        }
        return Response.ok(response).build();
    }

    private Response putEventSelectors(JsonNode request, String region) {
        service.putEventSelectors(region, request.path("TrailName").asText(null), request);
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response getEventSelectors(JsonNode request, String region) {
        CloudTrailService.GetEventSelectorsResult result = service.getEventSelectors(
                region, request.path("TrailName").asText(null));
        ObjectNode response = mapper.createObjectNode();
        response.put("TrailARN", result.trailArn());
        ArrayNode eventSelectors = response.putArray("EventSelectors");
        for (CloudTrailEventSelector selector : result.eventSelectors()) {
            eventSelectors.add(eventSelectorNode(selector));
        }
        if (result.advancedEventSelectors() != null) {
            ArrayNode advancedEventSelectors = response.putArray("AdvancedEventSelectors");
            for (CloudTrailAdvancedEventSelector selector : result.advancedEventSelectors()) {
                advancedEventSelectors.add(advancedEventSelectorNode(selector));
            }
        }
        return Response.ok(response).build();
    }

    private Response lookupEvents(JsonNode request, String region) {
        CloudTrailEventStore.LookupEventsResult result = service.lookupEvents(
                region,
                parseTimestamp(request.get("StartTime")),
                parseTimestamp(request.get("EndTime")),
                parseLookupAttributes(request.path("LookupAttributes")),
                readMaxResults(request),
                textOrNull(request, "NextToken"));

        ObjectNode response = mapper.createObjectNode();
        ArrayNode events = response.putArray("Events");
        for (CloudTrailEvent event : result.events()) {
            events.add(eventNode(event));
        }
        if (result.nextToken() != null) {
            response.put("NextToken", result.nextToken());
        }
        return Response.ok(response).build();
    }

    private ObjectNode eventNode(CloudTrailEvent event) {
        ObjectNode node = mapper.createObjectNode();
        node.put("EventId", event.getEventId());
        node.put("EventName", event.getEventName());
        if (event.getEventTime() != null) {
            node.put("EventTime", event.getEventTime().toEpochMilli() / 1000.0);
        }
        if (event.getUsername() != null) {
            node.put("Username", event.getUsername());
        }
        if (event.getEventSource() != null) {
            node.put("EventSource", event.getEventSource());
        }
        node.put("ReadOnly", event.isReadOnly() ? "true" : "false");
        if (event.getFullEventJson() != null) {
            node.put("CloudTrailEvent", event.getFullEventJson());
        }
        ArrayNode resources = node.putArray("Resources");
        if (event.getResources() != null && !event.getResources().isEmpty()) {
            for (CloudTrailEventResource resource : event.getResources()) {
                ObjectNode resourceNode = resources.addObject();
                if (resource.getResourceName() != null) {
                    resourceNode.put("ResourceName", resource.getResourceName());
                }
                if (resource.getResourceType() != null) {
                    resourceNode.put("ResourceType", resource.getResourceType());
                }
            }
        }
        return node;
    }

    private ObjectNode eventSelectorNode(CloudTrailEventSelector selector) {
        ObjectNode node = mapper.createObjectNode();
        if (selector.getReadWriteType() != null) {
            node.put("ReadWriteType", selector.getReadWriteType());
        }
        node.put("IncludeManagementEvents", selector.isIncludeManagementEvents());
        ArrayNode dataResources = node.putArray("DataResources");
        if (selector.getDataResources() != null) {
            for (CloudTrailDataResource dataResource : selector.getDataResources()) {
                ObjectNode dataResourceNode = dataResources.addObject();
                if (dataResource.getType() != null) {
                    dataResourceNode.put("Type", dataResource.getType());
                }
                ArrayNode values = dataResourceNode.putArray("Values");
                if (dataResource.getValues() != null) {
                    dataResource.getValues().forEach(values::add);
                }
            }
        }
        if (selector.getExcludeManagementEventSources() != null
                && !selector.getExcludeManagementEventSources().isEmpty()) {
            ArrayNode excludedSources = node.putArray("ExcludeManagementEventSources");
            selector.getExcludeManagementEventSources().forEach(excludedSources::add);
        }
        return node;
    }

    private ObjectNode advancedEventSelectorNode(CloudTrailAdvancedEventSelector selector) {
        ObjectNode node = mapper.createObjectNode();
        if (selector.getName() != null) {
            node.put("Name", selector.getName());
        }
        ArrayNode fieldSelectors = node.putArray("FieldSelectors");
        if (selector.getFieldSelectors() != null) {
            for (CloudTrailAdvancedFieldSelector fieldSelector : selector.getFieldSelectors()) {
                ObjectNode fieldSelectorNode = fieldSelectors.addObject();
                if (fieldSelector.getField() != null) {
                    fieldSelectorNode.put("Field", fieldSelector.getField());
                }
                if (fieldSelector.getEquals() != null && !fieldSelector.getEquals().isEmpty()) {
                    ArrayNode equals = fieldSelectorNode.putArray("Equals");
                    fieldSelector.getEquals().forEach(equals::add);
                }
                if (fieldSelector.getNotEquals() != null && !fieldSelector.getNotEquals().isEmpty()) {
                    ArrayNode notEquals = fieldSelectorNode.putArray("NotEquals");
                    fieldSelector.getNotEquals().forEach(notEquals::add);
                }
            }
        }
        return node;
    }

    private ObjectNode trailNode(CloudTrailTrail trail) {
        ObjectNode node = mapper.createObjectNode();
        node.put("Name", trail.getName());
        node.put("TrailARN", trail.getTrailArn());
        node.put("S3BucketName", trail.getS3BucketName());
        node.put("IncludeGlobalServiceEvents", trail.isIncludeGlobalServiceEvents());
        node.put("IsMultiRegionTrail", trail.isMultiRegionTrail());
        node.put("IsOrganizationTrail", trail.isOrganizationTrail());
        node.put("HomeRegion", trail.getHomeRegion());
        if (trail.getCreated() != null) {
            node.put("CreationDate", trail.getCreated().toEpochMilli() / 1000.0);
        }
        return node;
    }

    private static Map<String, String> parseTags(JsonNode tagsNode) {
        Map<String, String> tags = new HashMap<>();
        if (tagsNode != null && tagsNode.isArray()) {
            for (JsonNode tag : tagsNode) {
                String key = tag.path("Key").asText(null);
                if (key != null) {
                    tags.put(key, tag.path("Value").asText(""));
                }
            }
        }
        return tags;
    }

    private static List<String> stringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        java.util.ArrayList<String> values = new java.util.ArrayList<>();
        node.forEach(value -> values.add(value.asText()));
        return values;
    }

    private static Boolean optionalBoolean(JsonNode node, String fieldName) {
        return node != null && node.has(fieldName) ? node.path(fieldName).asBoolean() : null;
    }

    private static Instant parseTimestamp(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return null;
        }
        if (node.isNumber()) {
            double seconds = node.asDouble();
            long wholeSeconds = (long) seconds;
            long nanos = (long) ((seconds - wholeSeconds) * 1_000_000_000L);
            return Instant.ofEpochSecond(wholeSeconds, nanos);
        }
        String text = node.asText(null);
        if (text == null || text.isBlank()) {
            return null;
        }
        return Instant.parse(text);
    }

    private static List<CloudTrailEventStore.LookupAttribute> parseLookupAttributes(JsonNode attributesNode) {
        if (attributesNode == null || !attributesNode.isArray()) {
            return List.of();
        }
        List<CloudTrailEventStore.LookupAttribute> attributes = new ArrayList<>();
        attributesNode.forEach(attribute -> attributes.add(new CloudTrailEventStore.LookupAttribute(
                attribute.path("AttributeKey").asText(null),
                attribute.path("AttributeValue").asText(null))));
        return attributes;
    }

    private static Integer readMaxResults(JsonNode request) {
        JsonNode node = request.get("MaxResults");
        if (node == null || node.isNull()) {
            return null;
        }
        return node.asInt();
    }

    private static String textOrNull(JsonNode node, String fieldName) {
        JsonNode value = node.get(fieldName);
        if (value == null || value.isNull()) {
            return null;
        }
        String text = value.asText(null);
        return text == null || text.isBlank() ? null : text;
    }
}
