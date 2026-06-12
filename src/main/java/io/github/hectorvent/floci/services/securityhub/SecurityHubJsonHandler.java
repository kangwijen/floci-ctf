package io.github.hectorvent.floci.services.securityhub;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.securityhub.model.AwsSecurityFindingFormat;
import io.github.hectorvent.floci.services.securityhub.model.SecurityHubAccount;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
public class SecurityHubJsonHandler {

    private final SecurityHubService service;
    private final ObjectMapper mapper;

    @Inject
    public SecurityHubJsonHandler(SecurityHubService service, ObjectMapper mapper) {
        this.service = service;
        this.mapper = mapper;
    }

    public Response handle(String action, JsonNode request, String region) {
        return switch (action) {
            case "EnableSecurityHub" -> enableSecurityHub(region);
            case "DescribeHub" -> describeHub(region);
            case "GetFindings" -> getFindings(request, region);
            case "BatchImportFindings" -> batchImportFindings(request, region);
            case "BatchUpdateFindings" -> batchUpdateFindings(request, region);
            case "ListEnabledProductsForImport" -> listEnabledProductsForImport(region, request);
            default -> throw new AwsException("InvalidAction",
                    "Could not find operation " + action, 400);
        };
    }

    private Response enableSecurityHub(String region) {
        service.enableSecurityHub(region);
        return Response.ok(mapper.createObjectNode()).build();
    }

    private Response describeHub(String region) {
        SecurityHubAccount account = service.describeHub(region);
        ObjectNode response = mapper.createObjectNode();
        response.put("HubArn", account.getHubArn());
        response.put("AutoEnableControls", account.isAutoEnableControls());
        response.put("ControlFindingGenerator", account.getControlFindingGenerator());
        if (account.getSubscribedAt() != null) {
            response.put("SubscribedAt", DateTimeFormatter.ISO_INSTANT.format(account.getSubscribedAt()));
        }
        return Response.ok(response).build();
    }

    private Response getFindings(JsonNode request, String region) {
        JsonNode filters = request.path("Filters");
        Integer maxResults = request.has("MaxResults") ? request.path("MaxResults").asInt() : null;
        List<AwsSecurityFindingFormat> findings = service.getFindings(region, filters, maxResults);
        ObjectNode response = mapper.createObjectNode();
        response.set("Findings", mapper.valueToTree(findings));
        return Response.ok(response).build();
    }

    private Response batchImportFindings(JsonNode request, String region) {
        List<AwsSecurityFindingFormat> findings = new ArrayList<>();
        for (JsonNode node : request.path("Findings")) {
            try {
                findings.add(mapper.treeToValue(node, AwsSecurityFindingFormat.class));
            } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
                throw new AwsException("InvalidInputException", "Invalid finding payload", 400);
            }
        }
        if (findings.isEmpty()) {
            throw new AwsException("InvalidInputException", "Findings must not be empty", 400);
        }
        SecurityHubService.ImportResult result = service.batchImportFindings(region, findings);
        ObjectNode response = mapper.createObjectNode();
        response.put("SuccessCount", result.successCount());
        response.put("FailedCount", result.failedCount());
        ArrayNode failed = response.putArray("FailedFindings");
        for (SecurityHubService.ImportFailure failure : result.failedFindings()) {
            ObjectNode entry = failed.addObject();
            entry.put("Id", failure.id());
            entry.put("ErrorCode", failure.errorCode());
            entry.put("ErrorMessage", failure.errorMessage());
        }
        return Response.ok(response).build();
    }

    private Response batchUpdateFindings(JsonNode request, String region) {
        List<SecurityHubService.FindingIdentifier> identifiers = new ArrayList<>();
        for (JsonNode node : request.path("FindingIdentifiers")) {
            identifiers.add(new SecurityHubService.FindingIdentifier(
                    node.path("Id").asText(null),
                    node.path("ProductArn").asText(null)));
        }
        if (identifiers.isEmpty()) {
            throw new AwsException("InvalidInputException", "FindingIdentifiers must not be empty", 400);
        }
        AwsSecurityFindingFormat.Severity severity = null;
        if (request.has("Severity")) {
            severity = mapper.convertValue(request.path("Severity"), AwsSecurityFindingFormat.Severity.class);
        }
        AwsSecurityFindingFormat.Workflow workflow = null;
        if (request.has("Workflow")) {
            workflow = mapper.convertValue(request.path("Workflow"), AwsSecurityFindingFormat.Workflow.class);
        }
        SecurityHubService.BatchUpdateResult result = service.batchUpdateFindings(
                region, identifiers, severity, workflow);
        ObjectNode response = mapper.createObjectNode();
        ArrayNode processed = response.putArray("ProcessedFindings");
        for (SecurityHubService.FindingIdentifier identifier : result.processedFindings()) {
            ObjectNode entry = processed.addObject();
            entry.put("Id", identifier.id());
            entry.put("ProductArn", identifier.productArn());
        }
        ArrayNode unprocessed = response.putArray("UnprocessedFindings");
        for (SecurityHubService.UnprocessedFinding failure : result.unprocessedFindings()) {
            ObjectNode entry = unprocessed.addObject();
            entry.put("ErrorCode", failure.errorCode());
            entry.put("ErrorMessage", failure.errorMessage());
            ObjectNode idNode = entry.putObject("FindingIdentifier");
            idNode.put("Id", failure.findingIdentifier().id());
            idNode.put("ProductArn", failure.findingIdentifier().productArn());
        }
        return Response.ok(response).build();
    }

    private Response listEnabledProductsForImport(String region, JsonNode request) {
        List<String> products = service.listEnabledProductsForImport(region);
        ObjectNode response = mapper.createObjectNode();
        ArrayNode subscriptions = response.putArray("ProductSubscriptions");
        products.forEach(subscriptions::add);
        if (request.has("NextToken")) {
            response.putNull("NextToken");
        }
        return Response.ok(response).build();
    }
}
