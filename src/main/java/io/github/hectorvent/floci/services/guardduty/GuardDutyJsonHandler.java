package io.github.hectorvent.floci.services.guardduty;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.guardduty.model.GuardDutyDetector;
import io.github.hectorvent.floci.services.guardduty.model.GuardDutyFinding;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@ApplicationScoped
public class GuardDutyJsonHandler {

    private static final DateTimeFormatter GUARDDUTY_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private final GuardDutyService service;
    private final ObjectMapper mapper;

    @Inject
    public GuardDutyJsonHandler(GuardDutyService service, ObjectMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    public Response handle(String action, JsonNode request, String region) {
        return switch (action) {
            case "CreateDetector" -> createDetector(request, region);
            case "ListDetectors" -> listDetectors(region);
            case "GetDetector" -> getDetector(request, region);
            case "UpdateDetector" -> updateDetector(request, region);
            case "ListFindings" -> listFindings(request, region);
            case "GetFindings" -> getFindings(request, region);
            case "ArchiveFindings" -> archiveFindings(request, region);
            case "CreateSampleFindings" -> createSampleFindings(request, region);
            default -> throw new AwsException("InvalidInputException",
                    "Could not find operation " + action, 400);
        };
    }

    private Response createDetector(JsonNode request, String region) {
        String detectorId = service.createDetector(
                region,
                request.path("enable").asBoolean(true),
                request.path("findingPublishingFrequency").asText(null),
                parseTags(request.path("tags")));
        ObjectNode response = mapper.createObjectNode();
        response.put("detectorId", detectorId);
        return Response.ok(response).build();
    }

    private Response listDetectors(String region) {
        ObjectNode response = mapper.createObjectNode();
        ArrayNode detectorIds = response.putArray("detectorIds");
        for (String detectorId : service.listDetectors(region)) {
            detectorIds.add(detectorId);
        }
        return Response.ok(response).build();
    }

    private Response getDetector(JsonNode request, String region) {
        GuardDutyDetector detector = service.getDetector(region, request.path("DetectorId").asText(null));
        return Response.ok(detectorNode(detector)).build();
    }

    private Response updateDetector(JsonNode request, String region) {
        Boolean enable = request.has("enable") ? request.path("enable").asBoolean() : null;
        service.updateDetector(
                region,
                request.path("DetectorId").asText(null),
                enable,
                request.path("findingPublishingFrequency").asText(null));
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response listFindings(JsonNode request, String region) {
        List<String> findingIds = service.listFindings(
                region,
                request.path("DetectorId").asText(null),
                request.path("findingCriteria"),
                request.has("maxResults") ? request.path("maxResults").asInt() : null);
        ObjectNode response = mapper.createObjectNode();
        ArrayNode ids = response.putArray("findingIds");
        findingIds.forEach(ids::add);
        return Response.ok(response).build();
    }

    private Response getFindings(JsonNode request, String region) {
        List<GuardDutyFinding> findings = service.getFindings(
                region,
                request.path("DetectorId").asText(null),
                stringList(request.path("findingIds")));
        ObjectNode response = mapper.createObjectNode();
        ArrayNode findingsNode = response.putArray("findings");
        for (GuardDutyFinding finding : findings) {
            findingsNode.add(findingNode(finding));
        }
        return Response.ok(response).build();
    }

    private Response archiveFindings(JsonNode request, String region) {
        service.archiveFindings(
                region,
                request.path("DetectorId").asText(null),
                stringList(request.path("findingIds")));
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response createSampleFindings(JsonNode request, String region) {
        service.createSampleFindings(
                region,
                request.path("DetectorId").asText(null),
                stringList(request.path("findingTypes")));
        return Response.ok(mapper.createObjectNode()).build();
    }

    private ObjectNode detectorNode(GuardDutyDetector detector) {
        ObjectNode node = mapper.createObjectNode();
        node.put("status", detector.getStatus());
        node.put("findingPublishingFrequency", detector.getFindingPublishingFrequency());
        if (detector.getCreatedAt() != null) {
            node.put("createdAt", GUARDDUTY_TIMESTAMP.format(detector.getCreatedAt()));
        }
        if (detector.getUpdatedAt() != null) {
            node.put("updatedAt", GUARDDUTY_TIMESTAMP.format(detector.getUpdatedAt()));
        }
        if (detector.getTags() != null && !detector.getTags().isEmpty()) {
            ObjectNode tags = node.putObject("tags");
            detector.getTags().forEach(tags::put);
        }
        ObjectNode dataSources = node.putObject("dataSources");
        dataSources.putObject("cloudTrail").put("status", "ENABLED");
        dataSources.putObject("dnsLogs").put("status", "ENABLED");
        dataSources.putObject("flowLogs").put("status", "ENABLED");
        dataSources.putObject("s3Logs").put("status", "ENABLED");
        return node;
    }

    private ObjectNode findingNode(GuardDutyFinding finding) {
        ObjectNode node = mapper.createObjectNode();
        node.put("accountId", finding.getAccountId());
        node.put("arn", finding.getArn());
        node.put("id", finding.getId());
        node.put("partition", finding.getPartition());
        node.put("region", finding.getRegion());
        node.put("type", finding.getType());
        node.put("severity", finding.getSeverity());
        node.put("title", finding.getTitle());
        node.put("description", finding.getDescription());
        if (finding.getCreatedAt() != null) {
            node.put("createdAt", GUARDDUTY_TIMESTAMP.format(finding.getCreatedAt()));
        }
        if (finding.getUpdatedAt() != null) {
            node.put("updatedAt", GUARDDUTY_TIMESTAMP.format(finding.getUpdatedAt()));
        }
        if (finding.getResource() != null && !finding.getResource().isEmpty()) {
            node.set("resource", mapper.valueToTree(finding.getResource()));
        }
        if (finding.getService() != null && !finding.getService().isEmpty()) {
            node.set("service", mapper.valueToTree(finding.getService()));
        }
        return node;
    }

    private static Map<String, String> parseTags(JsonNode tagsNode) {
        Map<String, String> tags = new HashMap<>();
        if (tagsNode != null && tagsNode.isObject()) {
            tagsNode.fields().forEachRemaining(entry -> tags.put(entry.getKey(), entry.getValue().asText("")));
        }
        return tags;
    }

    private static List<String> stringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        node.forEach(value -> values.add(value.asText()));
        return values;
    }
}
