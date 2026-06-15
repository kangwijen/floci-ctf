package io.github.hectorvent.floci.services.guardduty;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.guardduty.model.GuardDutyDetector;
import io.github.hectorvent.floci.services.guardduty.model.GuardDutyFinding;
import io.github.hectorvent.floci.services.securityhub.GuardDutyFindingSubscriber;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;

@ApplicationScoped
public class GuardDutyService {

    private static final DateTimeFormatter GUARDDUTY_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private static final List<String> DEFAULT_SAMPLE_TYPES = List.of(
            "Recon:EC2/PortProbeUnprotectedPort",
            "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
            "Policy:IAMUser/RootCredentialUsage",
            "CryptoCurrency:EC2/BitcoinTool.B"
    );

    private static final Map<String, SuspiciousEventRule> CLOUDTRAIL_RULES = Map.of(
            "CreateAccessKey", new SuspiciousEventRule(
                    "CredentialAccess:IAMUser/AnomalousBehavior",
                    5.0,
                    "An IAM user created an access key outside the expected pattern.",
                    "IAM"),
            "DeleteBucket", new SuspiciousEventRule(
                    "Exfiltration:S3/ObjectDeleted",
                    6.0,
                    "An S3 bucket was deleted, which may indicate destructive activity.",
                    "S3"),
            "ConsoleLogin", new SuspiciousEventRule(
                    "UnauthorizedAccess:IAMUser/ConsoleLogin.Behavior",
                    4.0,
                    "A console login was observed with unusual characteristics.",
                    "IAM"),
            "StopLogging", new SuspiciousEventRule(
                    "DefenseEvasion:CloudTrail/StopLogging",
                    7.0,
                    "CloudTrail logging was stopped, which may indicate an attempt to evade detection.",
                    "CloudTrail"),
            "DeleteTrail", new SuspiciousEventRule(
                    "DefenseEvasion:CloudTrail/DeleteTrail",
                    8.0,
                    "A CloudTrail trail was deleted, which may indicate an attempt to destroy audit evidence.",
                    "CloudTrail")
    );

    private final StorageBackend<String, GuardDutyDetector> detectorStore;
    private final StorageBackend<String, GuardDutyFinding> findingStore;
    private final RegionResolver regionResolver;
    private final EmulatorConfig config;
    private final GuardDutyFindingSubscriber findingSubscriber;

    @Inject
    public GuardDutyService(StorageFactory storageFactory,
                            RegionResolver regionResolver,
                            EmulatorConfig config,
                            GuardDutyFindingSubscriber findingSubscriber) {
        this.detectorStore = storageFactory.create("guardduty", "guardduty-detectors.json",
                new TypeReference<Map<String, GuardDutyDetector>>() {});
        this.findingStore = storageFactory.create("guardduty", "guardduty-findings.json",
                new TypeReference<Map<String, GuardDutyFinding>>() {});
        this.regionResolver = regionResolver;
        this.config = config;
        this.findingSubscriber = findingSubscriber;
    }

    public String createDetector(String region, boolean enable, String findingPublishingFrequency,
                                 Map<String, String> tags) {
        if (detectorStore.scan(key -> key.startsWith(region + ":")).stream().findAny().isPresent()) {
            throw new AwsException("BadRequestException",
                    "The request is rejected because a detector already exists for the current account.", 400);
        }
        Instant now = Instant.now();
        GuardDutyDetector detector = new GuardDutyDetector();
        detector.setDetectorId(UUID.randomUUID().toString().replace("-", ""));
        detector.setRegion(region);
        detector.setEnabled(enable);
        detector.setStatus(enable ? "ENABLED" : "DISABLED");
        detector.setFindingPublishingFrequency(
                findingPublishingFrequency == null || findingPublishingFrequency.isBlank()
                        ? "SIX_HOURS"
                        : findingPublishingFrequency);
        detector.setCreatedAt(now);
        detector.setUpdatedAt(now);
        detector.setTags(tags == null ? Map.of() : tags);
        detectorStore.put(detectorKey(region, detector.getDetectorId()), detector);
        return detector.getDetectorId();
    }

    public List<String> listDetectors(String region) {
        return detectorStore.scan(key -> key.startsWith(region + ":")).stream()
                .map(GuardDutyDetector::getDetectorId)
                .toList();
    }

    public GuardDutyDetector getDetector(String region, String detectorId) {
        return requireDetector(region, detectorId);
    }

    public void updateDetector(String region, String detectorId, Boolean enable,
                               String findingPublishingFrequency) {
        GuardDutyDetector detector = requireDetector(region, detectorId);
        if (enable != null) {
            detector.setEnabled(enable);
            detector.setStatus(enable ? "ENABLED" : "DISABLED");
        }
        if (findingPublishingFrequency != null && !findingPublishingFrequency.isBlank()) {
            detector.setFindingPublishingFrequency(findingPublishingFrequency);
        }
        detector.setUpdatedAt(Instant.now());
        detectorStore.put(detectorKey(region, detectorId), detector);
    }

    public List<String> listFindings(String region, String detectorId, JsonNode findingCriteria,
                                     Integer maxResults) {
        requireDetector(region, detectorId);
        boolean archivedOnly = isArchivedFilter(findingCriteria, true);
        boolean unarchivedOnly = isArchivedFilter(findingCriteria, false);
        List<String> ids = findingStore.scan(findingKeyPrefix(region, detectorId)).stream()
                .filter(finding -> matchesArchivedFilter(finding, archivedOnly, unarchivedOnly))
                .map(GuardDutyFinding::getId)
                .toList();
        int limit = maxResults == null || maxResults <= 0 ? ids.size() : Math.min(maxResults, ids.size());
        return ids.subList(0, limit);
    }

    public List<GuardDutyFinding> getFindings(String region, String detectorId, List<String> findingIds) {
        requireDetector(region, detectorId);
        if (findingIds == null || findingIds.isEmpty()) {
            return List.of();
        }
        List<GuardDutyFinding> findings = new ArrayList<>();
        for (String findingId : findingIds) {
            findingStore.get(findingKey(region, detectorId, findingId))
                    .ifPresent(findings::add);
        }
        return findings;
    }

    public void archiveFindings(String region, String detectorId, List<String> findingIds) {
        requireDetector(region, detectorId);
        if (findingIds == null || findingIds.isEmpty()) {
            return;
        }
        Instant now = Instant.now();
        for (String findingId : findingIds) {
            Optional<GuardDutyFinding> stored = findingStore.get(findingKey(region, detectorId, findingId));
            if (stored.isPresent()) {
                GuardDutyFinding finding = stored.get();
                finding.setArchived(true);
                finding.setUpdatedAt(now);
                findingStore.put(findingKey(region, detectorId, findingId), finding);
            }
        }
    }

    public void createSampleFindings(String region, String detectorId, List<String> findingTypes) {
        requireDetector(region, detectorId);
        List<String> types = findingTypes == null || findingTypes.isEmpty()
                ? DEFAULT_SAMPLE_TYPES
                : findingTypes;
        for (String type : types) {
            GuardDutyFinding finding = buildSampleFinding(region, detectorId, type);
            persistFinding(finding);
        }
    }

    public void onCloudTrailEvent(String region, Map<String, Object> event) {
        if (!config.services().guardduty().enabled()) {
            return;
        }
        List<GuardDutyDetector> detectors = detectorStore.scan(key -> key.startsWith(region + ":"));
        if (detectors.isEmpty()) {
            return;
        }
        String eventName = event.get("eventName") instanceof String name ? name : null;
        if (eventName == null) {
            return;
        }
        SuspiciousEventRule rule = CLOUDTRAIL_RULES.get(eventName);
        if (rule == null) {
            return;
        }
        GuardDutyDetector detector = detectors.stream()
                .filter(GuardDutyDetector::isEnabled)
                .findFirst()
                .orElse(null);
        if (detector == null) {
            return;
        }
        GuardDutyFinding finding = buildCloudTrailFinding(region, detector.getDetectorId(), event, rule);
        persistFinding(finding);
    }

    private void persistFinding(GuardDutyFinding finding) {
        findingStore.put(
                findingKey(finding.getRegion(), finding.getDetectorId(), finding.getId()),
                finding);
        findingSubscriber.onGuardDutyFinding(finding.getRegion(), finding.getId());
    }

    private GuardDutyFinding buildCloudTrailFinding(String region,
                                                    String detectorId,
                                                    Map<String, Object> event,
                                                    SuspiciousEventRule rule) {
        String accountId = regionResolver.getAccountId();
        Instant now = Instant.now();
        GuardDutyFinding finding = new GuardDutyFinding();
        finding.setId(UUID.randomUUID().toString().replace("-", "").substring(0, 32));
        finding.setDetectorId(detectorId);
        finding.setRegion(region);
        finding.setAccountId(accountId);
        finding.setArn(findingArn(region, accountId, detectorId, finding.getId()));
        finding.setType(rule.type());
        finding.setSeverity(rule.severity());
        finding.setTitle(rule.type());
        finding.setDescription(rule.description());
        finding.setPartition("aws");
        finding.setCreatedAt(now);
        finding.setUpdatedAt(now);
        finding.setArchived(false);

        Map<String, Object> resource = new LinkedHashMap<>();
        resource.put("resourceType", rule.resourceType());
        if (event.get("userIdentity") instanceof Map<?, ?> userIdentity) {
            Map<String, Object> accessKeyDetails = new LinkedHashMap<>();
            Object accessKeyId = userIdentity.get("accessKeyId");
            if (accessKeyId != null) {
                accessKeyDetails.put("accessKeyId", accessKeyId);
            }
            Object userName = userIdentity.get("userName");
            if (userName != null) {
                accessKeyDetails.put("userName", userName);
            }
            Object principalId = userIdentity.get("principalId");
            if (principalId != null) {
                accessKeyDetails.put("principalId", principalId);
            }
            if (!accessKeyDetails.isEmpty()) {
                resource.put("accessKeyDetails", accessKeyDetails);
            }
        }
        finding.setResource(resource);

        Map<String, Object> service = new LinkedHashMap<>();
        service.put("archived", false);
        service.put("count", 1);
        service.put("eventFirstSeen", GUARDDUTY_TIMESTAMP.format(now));
        service.put("eventLastSeen", GUARDDUTY_TIMESTAMP.format(now));
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("actionType", "AWS_API_CALL");
        Map<String, Object> awsApiCallAction = new LinkedHashMap<>();
        awsApiCallAction.put("api", event.get("eventName"));
        awsApiCallAction.put("serviceName", event.get("eventSource"));
        action.put("awsApiCallAction", awsApiCallAction);
        service.put("action", action);
        finding.setService(service);
        return finding;
    }

    private GuardDutyFinding buildSampleFinding(String region, String detectorId, String type) {
        String accountId = regionResolver.getAccountId();
        Instant now = Instant.now();
        GuardDutyFinding finding = new GuardDutyFinding();
        finding.setId(UUID.randomUUID().toString().replace("-", "").substring(0, 32));
        finding.setDetectorId(detectorId);
        finding.setRegion(region);
        finding.setAccountId(accountId);
        finding.setArn(findingArn(region, accountId, detectorId, finding.getId()));
        finding.setType(type);
        finding.setSeverity(sampleSeverity(type));
        finding.setTitle(type);
        finding.setDescription(sampleDescription(type));
        finding.setPartition("aws");
        finding.setCreatedAt(now);
        finding.setUpdatedAt(now);
        finding.setArchived(false);
        finding.setResource(sampleResource(type, accountId, region));
        finding.setService(sampleService(type, now));
        return finding;
    }

    private Map<String, Object> sampleResource(String type, String accountId, String region) {
        Map<String, Object> resource = new LinkedHashMap<>();
        if (type.startsWith("Recon:EC2/")) {
            resource.put("resourceType", "Instance");
            Map<String, Object> instanceDetails = new LinkedHashMap<>();
            instanceDetails.put("instanceId", "i-0sample" + UUID.randomUUID().toString().substring(0, 8));
            instanceDetails.put("instanceType", "t3.micro");
            instanceDetails.put("launchTime", GUARDDUTY_TIMESTAMP.format(Instant.now()));
            resource.put("instanceDetails", instanceDetails);
        } else if (type.contains("IAMUser")) {
            resource.put("resourceType", "AccessKey");
            Map<String, Object> accessKeyDetails = new LinkedHashMap<>();
            accessKeyDetails.put("accessKeyId", "AKIA" + UUID.randomUUID().toString().replace("-", "").substring(0, 16).toUpperCase());
            accessKeyDetails.put("principalId", "AIDAI" + UUID.randomUUID().toString().replace("-", "").substring(0, 12).toUpperCase());
            accessKeyDetails.put("userName", "sample-user");
            accessKeyDetails.put("userType", "IAMUser");
            resource.put("accessKeyDetails", accessKeyDetails);
        } else {
            resource.put("resourceType", "Other");
        }
        resource.put("region", region);
        resource.put("accountId", accountId);
        return resource;
    }

    private Map<String, Object> sampleService(String type, Instant now) {
        Map<String, Object> service = new LinkedHashMap<>();
        service.put("archived", false);
        service.put("count", 1);
        service.put("eventFirstSeen", GUARDDUTY_TIMESTAMP.format(now));
        service.put("eventLastSeen", GUARDDUTY_TIMESTAMP.format(now));
        Map<String, Object> action = new LinkedHashMap<>();
        if (type.startsWith("Recon:")) {
            action.put("actionType", "NETWORK_CONNECTION");
            Map<String, Object> networkConnectionAction = new LinkedHashMap<>();
            networkConnectionAction.put("connectionDirection", "INBOUND");
            networkConnectionAction.put("protocol", "TCP");
            action.put("networkConnectionAction", networkConnectionAction);
        } else if (type.contains("CryptoCurrency")) {
            action.put("actionType", "DNS_REQUEST");
            Map<String, Object> dnsRequestAction = new LinkedHashMap<>();
            dnsRequestAction.put("domain", "pool.minergate.com");
            action.put("dnsRequestAction", dnsRequestAction);
        } else {
            action.put("actionType", "AWS_API_CALL");
            Map<String, Object> awsApiCallAction = new LinkedHashMap<>();
            awsApiCallAction.put("api", "ConsoleLogin");
            awsApiCallAction.put("serviceName", "iam.amazonaws.com");
            action.put("awsApiCallAction", awsApiCallAction);
        }
        service.put("action", action);
        service.put("detectorId", type);
        return service;
    }

    private static double sampleSeverity(String type) {
        if (type.contains("CryptoCurrency") || type.contains("RootCredential")) {
            return 8.0;
        }
        if (type.contains("UnauthorizedAccess") || type.contains("MaliciousIP")) {
            return 7.0;
        }
        if (type.startsWith("Recon:")) {
            return 2.0;
        }
        return 5.0;
    }

    private static String sampleDescription(String type) {
        return switch (type) {
            case "Recon:EC2/PortProbeUnprotectedPort" ->
                    "An unprotected port on EC2 instance i-0sample was probed from a suspicious host.";
            case "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom" ->
                    "API calls were made from a known malicious IP address by IAM user sample-user.";
            case "Policy:IAMUser/RootCredentialUsage" ->
                    "Root credentials were used to perform an API call in the account.";
            case "CryptoCurrency:EC2/BitcoinTool.B" ->
                    "EC2 instance is communicating with a known cryptocurrency mining pool.";
            default -> "Sample GuardDuty finding of type " + type + ".";
        };
    }

    private GuardDutyDetector requireDetector(String region, String detectorId) {
        if (detectorId == null || detectorId.isBlank()) {
            throw new AwsException("BadRequestException", "Detector ID is required", 400);
        }
        return detectorStore.get(detectorKey(region, detectorId))
                .orElseThrow(() -> new AwsException("BadRequestException",
                        "The input detectorId " + detectorId + " is not owned by the current account.", 400));
    }

    private String findingArn(String region, String accountId, String detectorId, String findingId) {
        return "arn:aws:guardduty:" + region + ":" + accountId + ":detector/" + detectorId + "/finding/" + findingId;
    }

    private static String detectorKey(String region, String detectorId) {
        return region + ":" + detectorId;
    }

    private static String findingKey(String region, String detectorId, String findingId) {
        return region + ":" + detectorId + ":" + findingId;
    }

    private static Predicate<String> findingKeyPrefix(String region, String detectorId) {
        return key -> key.startsWith(region + ":" + detectorId + ":");
    }

    private static boolean isArchivedFilter(JsonNode findingCriteria, boolean archivedValue) {
        if (findingCriteria == null || findingCriteria.isMissingNode()) {
            return false;
        }
        JsonNode criterion = findingCriteria.path("criterion");
        if (!criterion.isObject()) {
            return false;
        }
        JsonNode archived = criterion.path("service.archived");
        if (!archived.isObject()) {
            return false;
        }
        JsonNode equals = archived.path("equals");
        if (equals.isArray() && !equals.isEmpty()) {
            return Boolean.toString(archivedValue).equalsIgnoreCase(equals.get(0).asText());
        }
        JsonNode eq = archived.path("eq");
        if (eq.isArray() && !eq.isEmpty()) {
            return Boolean.toString(archivedValue).equalsIgnoreCase(eq.get(0).asText());
        }
        return false;
    }

    private static boolean matchesArchivedFilter(GuardDutyFinding finding,
                                                 boolean archivedOnly,
                                                 boolean unarchivedOnly) {
        if (archivedOnly) {
            return finding.isArchived();
        }
        if (unarchivedOnly) {
            return !finding.isArchived();
        }
        return true;
    }

    private record SuspiciousEventRule(String type, double severity, String description, String resourceType) {}
}
