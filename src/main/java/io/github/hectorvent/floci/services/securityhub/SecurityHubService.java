package io.github.hectorvent.floci.services.securityhub;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.securityhub.model.AwsSecurityFindingFormat;
import io.github.hectorvent.floci.services.securityhub.model.SecurityHubAccount;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;

@ApplicationScoped
public class SecurityHubService {

    private static final DateTimeFormatter ASFF_TIMESTAMP =
            DateTimeFormatter.ISO_INSTANT;

    private final StorageBackend<String, SecurityHubAccount> accountStore;
    private final StorageBackend<String, AwsSecurityFindingFormat> findingStore;
    private final RegionResolver regionResolver;

    @Inject
    public SecurityHubService(StorageFactory storageFactory, RegionResolver regionResolver) {
        this.accountStore = storageFactory.create("securityhub", "securityhub-accounts.json",
                new TypeReference<Map<String, SecurityHubAccount>>() {});
        this.findingStore = storageFactory.create("securityhub", "securityhub-findings.json",
                new TypeReference<Map<String, AwsSecurityFindingFormat>>() {});
        this.regionResolver = regionResolver;
    }

    public void enableSecurityHub(String region) {
        if (isEnabled(region)) {
            throw new AwsException("ResourceConflictException",
                    "Security Hub is already enabled for this account", 409);
        }
        SecurityHubAccount account = new SecurityHubAccount();
        account.setHubArn(hubArn(region));
        account.setSubscribedAt(Instant.now());
        accountStore.put(region, account);
    }

    public SecurityHubAccount describeHub(String region) {
        return accountStore.get(region)
                .filter(account -> account.getHubArn() != null)
                .orElseThrow(() -> new AwsException("ResourceNotFoundException",
                        "Hub not found for account", 404));
    }

    public boolean isEnabled(String region) {
        return accountStore.get(region)
                .map(account -> account.getHubArn() != null)
                .orElse(false);
    }

    public ImportResult batchImportFindings(String region, List<AwsSecurityFindingFormat> findings) {
        requireEnabled(region);
        int success = 0;
        List<ImportFailure> failures = new ArrayList<>();
        for (AwsSecurityFindingFormat finding : findings) {
            try {
                validateFinding(finding);
                normalizeFinding(region, finding);
                findingStore.put(findingKey(region, finding), finding);
                success++;
            } catch (AwsException e) {
                failures.add(new ImportFailure(finding.getId(), e.getErrorCode(), e.getMessage()));
            }
        }
        return new ImportResult(success, failures.size(), failures);
    }

    public List<AwsSecurityFindingFormat> getFindings(String region, JsonNode filters, Integer maxResults) {
        requireEnabled(region);
        List<AwsSecurityFindingFormat> findings = findingStore.scan(key -> key.startsWith(region + ":"));
        List<AwsSecurityFindingFormat> filtered = findings.stream()
                .filter(finding -> matchesFilters(finding, filters))
                .toList();
        int limit = maxResults == null || maxResults <= 0 ? filtered.size() : Math.min(maxResults, filtered.size());
        return filtered.subList(0, limit);
    }

    public BatchUpdateResult batchUpdateFindings(String region, List<FindingIdentifier> identifiers,
                                                 AwsSecurityFindingFormat.Severity severity,
                                                 AwsSecurityFindingFormat.Workflow workflow) {
        requireEnabled(region);
        List<FindingIdentifier> processed = new ArrayList<>();
        List<UnprocessedFinding> unprocessed = new ArrayList<>();
        for (FindingIdentifier identifier : identifiers) {
            String key = findingKey(region, identifier.productArn(), identifier.id());
            Optional<AwsSecurityFindingFormat> stored = findingStore.get(key);
            if (stored.isEmpty()) {
                unprocessed.add(new UnprocessedFinding(identifier, "FindingNotFound",
                        "Finding not found"));
                continue;
            }
            AwsSecurityFindingFormat finding = stored.get();
            if (severity != null) {
                finding.setSeverity(severity);
            }
            if (workflow != null) {
                finding.setWorkflow(workflow);
            }
            finding.setUpdatedAt(ASFF_TIMESTAMP.format(Instant.now()));
            findingStore.put(key, finding);
            processed.add(identifier);
        }
        return new BatchUpdateResult(processed, unprocessed);
    }

    public List<String> listEnabledProductsForImport(String region) {
        requireEnabled(region);
        return List.of();
    }

    private void requireEnabled(String region) {
        if (!isEnabled(region)) {
            throw new AwsException("InvalidAccessException",
                    "Security Hub is not enabled for this account", 401);
        }
    }

    private void validateFinding(AwsSecurityFindingFormat finding) {
        if (finding.getId() == null || finding.getId().isBlank()) {
            throw new AwsException("InvalidInputException", "Finding Id is required", 400);
        }
        if (finding.getProductArn() == null || finding.getProductArn().isBlank()) {
            throw new AwsException("InvalidInputException", "Finding ProductArn is required", 400);
        }
    }

    private void normalizeFinding(String region, AwsSecurityFindingFormat finding) {
        if (finding.getAwsAccountId() == null || finding.getAwsAccountId().isBlank()) {
            finding.setAwsAccountId(regionResolver.getAccountId());
        }
        if (finding.getRegion() == null || finding.getRegion().isBlank()) {
            finding.setRegion(region);
        }
        if (finding.getSchemaVersion() == null || finding.getSchemaVersion().isBlank()) {
            finding.setSchemaVersion("2018-10-08");
        }
        if (finding.getRecordState() == null || finding.getRecordState().isBlank()) {
            finding.setRecordState("ACTIVE");
        }
        Instant now = Instant.now();
        String timestamp = ASFF_TIMESTAMP.format(now);
        if (finding.getCreatedAt() == null || finding.getCreatedAt().isBlank()) {
            finding.setCreatedAt(timestamp);
        }
        finding.setUpdatedAt(timestamp);
        if (finding.getWorkflow() == null) {
            AwsSecurityFindingFormat.Workflow workflow = new AwsSecurityFindingFormat.Workflow();
            workflow.setStatus("NEW");
            finding.setWorkflow(workflow);
        }
    }

    private boolean matchesFilters(AwsSecurityFindingFormat finding, JsonNode filters) {
        if (filters == null || filters.isNull() || filters.isEmpty()) {
            return true;
        }
        return matchesStringFilter(filters, "SeverityLabel", value ->
                        finding.getSeverity() != null && value.equals(finding.getSeverity().getLabel()))
                && matchesStringFilter(filters, "ProductArn", value ->
                        value.equals(finding.getProductArn()))
                && matchesStringFilter(filters, "ComplianceStatus", value ->
                        finding.getCompliance() != null && value.equals(finding.getCompliance().getStatus()));
    }

    private static boolean matchesStringFilter(JsonNode filters, String fieldName, Predicate<String> matcher) {
        JsonNode criteria = filters.path(fieldName);
        if (criteria.isMissingNode() || !criteria.isArray() || criteria.isEmpty()) {
            return true;
        }
        for (JsonNode criterion : criteria) {
            String comparison = criterion.path("Comparison").asText("EQUALS");
            String value = criterion.path("Value").asText(null);
            if (value == null) {
                continue;
            }
            if ("EQUALS".equals(comparison) && matcher.test(value)) {
                return true;
            }
        }
        return false;
    }

    private String hubArn(String region) {
        return regionResolver.buildArn("securityhub", region, "hub/default");
    }

    private static String findingKey(String region, AwsSecurityFindingFormat finding) {
        return findingKey(region, finding.getProductArn(), finding.getId());
    }

    private static String findingKey(String region, String productArn, String id) {
        return region + ":" + productArn + ":" + id;
    }

    public record FindingIdentifier(String id, String productArn) {
    }

    public record ImportFailure(String id, String errorCode, String errorMessage) {
    }

    public record ImportResult(int successCount, int failedCount, List<ImportFailure> failedFindings) {
    }

    public record UnprocessedFinding(FindingIdentifier findingIdentifier, String errorCode, String errorMessage) {
    }

    public record BatchUpdateResult(List<FindingIdentifier> processedFindings,
                                    List<UnprocessedFinding> unprocessedFindings) {
    }
}
