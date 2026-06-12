package io.github.hectorvent.floci.services.configservice;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailService;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailTrail;
import io.github.hectorvent.floci.services.configservice.model.ConfigSnapshotRecord;
import io.github.hectorvent.floci.services.configservice.model.ConfigurationItem;
import io.github.hectorvent.floci.services.configservice.model.ConfigurationItemHistory;
import io.github.hectorvent.floci.services.configservice.model.DeliveryChannel;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.Bucket;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@ApplicationScoped
public class ConfigSnapshotDeliveryService {

    private static final Logger LOG = Logger.getLogger(ConfigSnapshotDeliveryService.class);
    private static final String CONFIG_ITEM_VERSION = "1.3";
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmssSSS'Z'").withZone(ZoneOffset.UTC);

    private final StorageBackend<String, ConfigSnapshotRecord> snapshotIndex;
    private final StorageBackend<String, ConfigurationItemHistory> itemHistoryStore;
    private final S3Service s3Service;
    private final IamService iamService;
    private final CloudTrailService cloudTrailService;
    private final RegionResolver regionResolver;
    private final ObjectMapper mapper;

    @Inject
    public ConfigSnapshotDeliveryService(StorageFactory storageFactory,
                                         S3Service s3Service,
                                         IamService iamService,
                                         CloudTrailService cloudTrailService,
                                         RegionResolver regionResolver,
                                         ObjectMapper mapper) {
        this.snapshotIndex = storageFactory.create("config", "config-snapshot-index.json",
                new TypeReference<Map<String, ConfigSnapshotRecord>>() {});
        this.itemHistoryStore = storageFactory.create("config", "config-item-history.json",
                new TypeReference<Map<String, ConfigurationItemHistory>>() {});
        this.s3Service = s3Service;
        this.iamService = iamService;
        this.cloudTrailService = cloudTrailService;
        this.regionResolver = regionResolver;
        this.mapper = mapper;
    }

    ConfigSnapshotDeliveryService(StorageBackend<String, ConfigSnapshotRecord> snapshotIndex,
                                  StorageBackend<String, ConfigurationItemHistory> itemHistoryStore,
                                  S3Service s3Service,
                                  IamService iamService,
                                  CloudTrailService cloudTrailService,
                                  RegionResolver regionResolver,
                                  ObjectMapper mapper) {
        this.snapshotIndex = snapshotIndex;
        this.itemHistoryStore = itemHistoryStore;
        this.s3Service = s3Service;
        this.iamService = iamService;
        this.cloudTrailService = cloudTrailService;
        this.regionResolver = regionResolver;
        this.mapper = mapper;
    }

    public String deliverConfigurationSnapshot(String region, DeliveryChannel channel) {
        if (channel == null || channel.s3BucketName() == null || channel.s3BucketName().isBlank()) {
            return null;
        }
        List<ConfigurationItem> items = collectConfigurationItems(region);
        for (ConfigurationItem item : items) {
            storeConfigurationItem(region, item);
        }
        Instant now = Instant.now();
        String timestamp = TIMESTAMP_FORMAT.format(now);
        String s3Key = buildSnapshotS3Key(channel, timestamp);
        byte[] snapshotJson = writeSnapshotJson(items);
        s3Service.putObject(channel.s3BucketName(), s3Key, snapshotJson, "application/json", Map.of());
        ConfigSnapshotRecord record = new ConfigSnapshotRecord(
                timestamp,
                region,
                channel.s3BucketName(),
                s3Key,
                now.toEpochMilli() / 1000.0,
                items.size());
        snapshotIndex.put(snapshotKey(region, timestamp), record);
        LOG.infov("Delivered Config snapshot to s3://{0}/{1} ({2} items)",
                channel.s3BucketName(), s3Key, items.size());
        return timestamp;
    }

    public void captureConfigurationItem(String region, String resourceType, String resourceId) {
        ConfigurationItem item = buildConfigurationItem(region, resourceType, resourceId);
        if (item != null) {
            storeConfigurationItem(region, item);
        }
    }

    public List<ConfigurationItem> getResourceConfigHistory(String region,
                                                            String resourceType,
                                                            String resourceId,
                                                            Double laterTime,
                                                            Double earlierTime,
                                                            int limit) {
        String arn = resolveResourceArn(region, resourceType, resourceId);
        ConfigurationItemHistory history = itemHistoryStore.get(historyKey(region, arn))
                .orElse(new ConfigurationItemHistory());
        List<ConfigurationItem> filtered = new ArrayList<>();
        for (ConfigurationItem item : history.getItems()) {
            double captureTime = item.configurationItemCaptureTime() != null
                    ? item.configurationItemCaptureTime()
                    : 0.0;
            if (laterTime != null && captureTime >= laterTime) {
                continue;
            }
            if (earlierTime != null && captureTime <= earlierTime) {
                continue;
            }
            filtered.add(item);
        }
        if (limit > 0 && filtered.size() > limit) {
            int fromIndex = filtered.size() - limit;
            return new ArrayList<>(filtered.subList(fromIndex, filtered.size()));
        }
        return filtered;
    }

    public List<ConfigurationItem> batchGetResourceConfig(String region,
                                                          List<ResourceKey> resourceKeys) {
        List<ConfigurationItem> result = new ArrayList<>();
        for (ResourceKey key : resourceKeys) {
            String arn = resolveResourceArn(region, key.resourceType(), key.resourceId());
            itemHistoryStore.get(historyKey(region, arn))
                    .map(ConfigurationItemHistory::getItems)
                    .filter(items -> !items.isEmpty())
                    .map(items -> items.get(items.size() - 1))
                    .ifPresent(result::add);
        }
        return result;
    }

    public List<ConfigurationItem> collectConfigurationItems(String region) {
        List<ConfigurationItem> items = new ArrayList<>();
        for (IamUser user : iamService.listUsers(null)) {
            items.add(buildIamUserItem(region, user));
        }
        for (Bucket bucket : s3Service.listBuckets()) {
            items.add(buildS3BucketItem(region, bucket));
        }
        for (CloudTrailTrail trail : cloudTrailService.describeTrails(region, List.of())) {
            items.add(buildCloudTrailItem(region, trail));
        }
        return items;
    }

    private ConfigurationItem buildConfigurationItem(String region, String resourceType, String resourceId) {
        return switch (resourceType) {
            case "AWS::IAM::User" -> {
                try {
                    yield buildIamUserItem(region, iamService.getUser(resourceId));
                } catch (AwsException e) {
                    yield null;
                }
            }
            case "AWS::S3::Bucket" -> s3Service.listBuckets().stream()
                    .filter(b -> resourceId.equals(b.getName()))
                    .findFirst()
                    .map(bucket -> buildS3BucketItem(region, bucket))
                    .orElse(null);
            case "AWS::CloudTrail::Trail" -> cloudTrailService.describeTrails(region, List.of(resourceId)).stream()
                    .findFirst()
                    .map(trail -> buildCloudTrailItem(region, trail))
                    .orElse(null);
            default -> null;
        };
    }

    private ConfigurationItem buildIamUserItem(String region, IamUser user) {
        Map<String, Object> configuration = new LinkedHashMap<>();
        configuration.put("userName", user.getUserName());
        configuration.put("userId", user.getUserId());
        configuration.put("path", user.getPath());
        configuration.put("arn", user.getArn());
        if (user.getCreateDate() != null) {
            configuration.put("createDate", user.getCreateDate().toString());
        }
        configuration.put("attachedManagedPolicies", user.getAttachedPolicyArns());
        configuration.put("groupList", user.getGroupNames());
        return newItem(region, user.getArn(), "AWS::IAM::User", user.getUserName(),
                user.getUserName(), "Global", configuration, user.getTags());
    }

    private ConfigurationItem buildS3BucketItem(String region, Bucket bucket) {
        String arn = "arn:aws:s3:::" + bucket.getName();
        Map<String, Object> configuration = new LinkedHashMap<>();
        configuration.put("name", bucket.getName());
        if (bucket.getCreationDate() != null) {
            configuration.put("creationDate", bucket.getCreationDate().toString());
        }
        configuration.put("versioning", bucket.getVersioningStatus());
        configuration.put("region", bucket.getRegion() != null ? bucket.getRegion() : region);
        configuration.put("objectLockEnabled", bucket.isObjectLockEnabled());
        return newItem(region, arn, "AWS::S3::Bucket", bucket.getName(),
                bucket.getName(), "Regional", configuration, bucket.getTags());
    }

    private ConfigurationItem buildCloudTrailItem(String region, CloudTrailTrail trail) {
        Map<String, Object> configuration = new LinkedHashMap<>();
        configuration.put("name", trail.getName());
        configuration.put("s3BucketName", trail.getS3BucketName());
        configuration.put("includeGlobalServiceEvents", trail.isIncludeGlobalServiceEvents());
        configuration.put("isMultiRegionTrail", trail.isMultiRegionTrail());
        configuration.put("isOrganizationTrail", trail.isOrganizationTrail());
        configuration.put("isLogging", trail.isLogging());
        configuration.put("homeRegion", trail.getHomeRegion());
        return newItem(region, trail.getTrailArn(), "AWS::CloudTrail::Trail", trail.getName(),
                trail.getName(), "Regional", configuration, trail.getTags());
    }

    private ConfigurationItem newItem(String region,
                                      String arn,
                                      String resourceType,
                                      String resourceId,
                                      String resourceName,
                                      String availabilityZone,
                                      Map<String, Object> configuration,
                                      Map<String, String> tags) {
        double captureTime = Instant.now().toEpochMilli() / 1000.0;
        String configJson = writeConfigurationJson(configuration);
        return new ConfigurationItem(
                CONFIG_ITEM_VERSION,
                regionResolver.getAccountId(),
                captureTime,
                "OK",
                UUID.randomUUID().toString(),
                arn,
                resourceType,
                resourceId,
                resourceName,
                region,
                availabilityZone,
                configuration,
                Map.of(),
                tags != null ? tags : Map.of(),
                md5Hex(configJson));
    }

    private void storeConfigurationItem(String region, ConfigurationItem item) {
        String key = historyKey(region, item.arn());
        ConfigurationItemHistory history = itemHistoryStore.get(key)
                .orElseGet(ConfigurationItemHistory::new);
        history.getItems().add(item);
        itemHistoryStore.put(key, history);
    }

    private String buildSnapshotS3Key(DeliveryChannel channel, String timestamp) {
        String accountId = regionResolver.getAccountId();
        String date = DATE_FORMAT.format(Instant.now());
        String suffix = "AWSLogs/" + accountId + "/Config/ConfigSnapshot/" + date
                + "/ConfigSnapshot-" + timestamp + ".json";
        if (channel.s3KeyPrefix() != null && !channel.s3KeyPrefix().isBlank()) {
            String prefix = channel.s3KeyPrefix();
            if (prefix.endsWith("/")) {
                prefix = prefix.substring(0, prefix.length() - 1);
            }
            return prefix + "/" + suffix;
        }
        return suffix;
    }

    private byte[] writeSnapshotJson(List<ConfigurationItem> items) {
        try {
            ObjectNode root = mapper.createObjectNode();
            root.set("configurationItems", mapper.valueToTree(items));
            return mapper.writeValueAsBytes(root);
        } catch (Exception e) {
            throw new AwsException("InternalFailure", "Failed to serialize Config snapshot", 500);
        }
    }

    private String writeConfigurationJson(Map<String, Object> configuration) {
        try {
            return mapper.writeValueAsString(configuration);
        } catch (Exception e) {
            throw new AwsException("InternalFailure", "Failed to serialize configuration", 500);
        }
    }

    private String resolveResourceArn(String region, String resourceType, String resourceId) {
        String accountId = regionResolver.getAccountId();
        return switch (resourceType) {
            case "AWS::IAM::User" -> AwsArnUtils.Arn.of("iam", "", accountId, "user/" + resourceId).toString();
            case "AWS::S3::Bucket" -> "arn:aws:s3:::" + resourceId;
            case "AWS::CloudTrail::Trail" ->
                    AwsArnUtils.Arn.of("cloudtrail", region, accountId, "trail/" + resourceId).toString();
            default -> throw new AwsException("InvalidParameterValueException",
                    "Unsupported resource type: " + resourceType, 400);
        };
    }

    private static String snapshotKey(String region, String snapshotId) {
        return region + ":" + snapshotId;
    }

    private static String historyKey(String region, String arn) {
        return region + ":" + arn;
    }

    private static String md5Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 not available", e);
        }
    }

    public record ResourceKey(String resourceType, String resourceId) {
    }
}
