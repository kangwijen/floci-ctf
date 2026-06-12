package io.github.hectorvent.floci.services.configservice;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Optional hook for services that mutate emulated resources. When the Config
 * recorder is running in a region, captures an updated configuration item.
 */
@ApplicationScoped
public class ConfigResourceChangeNotifier {

    private static final Logger LOG = Logger.getLogger(ConfigResourceChangeNotifier.class);

    private final AwsConfigService configService;
    private final ConfigSnapshotDeliveryService snapshotDeliveryService;

    @Inject
    public ConfigResourceChangeNotifier(AwsConfigService configService,
                                        ConfigSnapshotDeliveryService snapshotDeliveryService) {
        this.configService = configService;
        this.snapshotDeliveryService = snapshotDeliveryService;
    }

    public void notifyResourceChanged(String region, String resourceType, String resourceId) {
        if (!configService.isRecorderRunning(region)) {
            return;
        }
        LOG.debugv("Capturing Config item for {0} {1} in {2}", resourceType, resourceId, region);
        snapshotDeliveryService.captureConfigurationItem(region, resourceType, resourceId);
    }
}
