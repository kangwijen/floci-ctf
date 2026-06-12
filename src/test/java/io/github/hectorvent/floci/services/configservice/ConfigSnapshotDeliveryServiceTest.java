package io.github.hectorvent.floci.services.configservice;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailService;
import io.github.hectorvent.floci.services.configservice.model.ConfigSnapshotRecord;
import io.github.hectorvent.floci.services.configservice.model.ConfigurationItem;
import io.github.hectorvent.floci.services.configservice.model.ConfigurationItemHistory;
import io.github.hectorvent.floci.services.configservice.model.DeliveryChannel;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.Bucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ConfigSnapshotDeliveryServiceTest {

    @Mock
    S3Service s3Service;

    @Mock
    IamService iamService;

    @Mock
    CloudTrailService cloudTrailService;

    private ConfigSnapshotDeliveryService deliveryService;
    private InMemoryStorage<String, ConfigSnapshotRecord> snapshotIndex;
    private InMemoryStorage<String, ConfigurationItemHistory> itemHistory;

    @BeforeEach
    void setUp() {
        snapshotIndex = new InMemoryStorage<>();
        itemHistory = new InMemoryStorage<>();
        RegionResolver regionResolver = new RegionResolver("us-east-1", "000000000000");
        deliveryService = new ConfigSnapshotDeliveryService(
                snapshotIndex,
                itemHistory,
                s3Service,
                iamService,
                cloudTrailService,
                regionResolver,
                new ObjectMapper());
    }

    @Test
    void deliverConfigurationSnapshotWritesAwsLikeS3Key() {
        IamUser user = new IamUser("AIDA123", "snapshot-user", "/", "arn:aws:iam::000000000000:user/snapshot-user");
        when(iamService.listUsers(null)).thenReturn(List.of(user));
        when(s3Service.listBuckets()).thenReturn(List.of(new Bucket("delivery-bucket")));
        when(cloudTrailService.describeTrails(eq("us-east-1"), any())).thenReturn(List.of());

        DeliveryChannel channel = new DeliveryChannel("default", "delivery-bucket", "prefix", null, null, null);
        String snapshotId = deliveryService.deliverConfigurationSnapshot("us-east-1", channel);

        assertNotNull(snapshotId);
        verify(s3Service).putObject(eq("delivery-bucket"), argThat(key ->
                        key.startsWith("prefix/AWSLogs/000000000000/Config/ConfigSnapshot/")
                                && key.contains("/ConfigSnapshot-")
                                && key.endsWith(".json")),
                any(byte[].class), eq("application/json"), anyMap());
        assertEquals(1, snapshotIndex.keys().size());
    }

    @Test
    void getResourceConfigHistoryReturnsStoredItems() {
        IamUser user = new IamUser("AIDA456", "history-user", "/", "arn:aws:iam::000000000000:user/history-user");
        when(iamService.listUsers(null)).thenReturn(List.of(user));
        when(s3Service.listBuckets()).thenReturn(List.of());
        when(cloudTrailService.describeTrails(eq("us-east-1"), any())).thenReturn(List.of());

        deliveryService.deliverConfigurationSnapshot("us-east-1",
                new DeliveryChannel("default", "delivery-bucket", null, null, null, null));

        List<ConfigurationItem> history = deliveryService.getResourceConfigHistory(
                "us-east-1", "AWS::IAM::User", "history-user", null, null, 10);
        assertEquals(1, history.size());
        assertEquals("AWS::IAM::User", history.getFirst().resourceType());
        assertEquals("history-user", history.getFirst().resourceId());
    }

    @Test
    void batchGetResourceConfigReturnsLatestPerResource() {
        IamUser user = new IamUser("AIDA789", "batch-user", "/", "arn:aws:iam::000000000000:user/batch-user");
        when(iamService.listUsers(null)).thenReturn(List.of(user));
        when(s3Service.listBuckets()).thenReturn(List.of(new Bucket("batch-bucket")));
        when(cloudTrailService.describeTrails(eq("us-east-1"), any())).thenReturn(List.of());

        deliveryService.deliverConfigurationSnapshot("us-east-1",
                new DeliveryChannel("default", "delivery-bucket", null, null, null, null));

        List<ConfigurationItem> items = deliveryService.batchGetResourceConfig("us-east-1", List.of(
                new ConfigSnapshotDeliveryService.ResourceKey("AWS::IAM::User", "batch-user"),
                new ConfigSnapshotDeliveryService.ResourceKey("AWS::S3::Bucket", "batch-bucket")));
        assertEquals(2, items.size());
    }
}
