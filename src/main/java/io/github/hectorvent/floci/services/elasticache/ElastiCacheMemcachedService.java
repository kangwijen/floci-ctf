package io.github.hectorvent.floci.services.elasticache;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.port.PortAllocator;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.elasticache.container.ElastiCacheContainerHandle;
import io.github.hectorvent.floci.services.elasticache.container.ElastiCacheMemcachedContainerManager;
import io.github.hectorvent.floci.services.elasticache.model.CacheCluster;
import io.github.hectorvent.floci.services.elasticache.model.CacheClusterStatus;
import io.github.hectorvent.floci.services.elasticache.model.Endpoint;
import io.github.hectorvent.floci.services.elasticache.proxy.ElastiCacheMemcachedProxyManager;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class ElastiCacheMemcachedService {

    private static final Logger LOG = Logger.getLogger(ElastiCacheMemcachedService.class);
    private static final String ENGINE = "memcached";
    private static final String ENGINE_VERSION = "1.6.22";

    private final StorageBackend<String, CacheCluster> clusters;
    private final ElastiCacheMemcachedContainerManager containerManager;
    private final ElastiCacheMemcachedProxyManager proxyManager;
    private final EmulatorConfig config;
    private final Set<Integer> usedPorts = ConcurrentHashMap.newKeySet();

    @Inject
    public ElastiCacheMemcachedService(ElastiCacheMemcachedContainerManager containerManager,
                                       ElastiCacheMemcachedProxyManager proxyManager,
                                       StorageFactory storageFactory,
                                       EmulatorConfig config) {
        this.containerManager = containerManager;
        this.proxyManager = proxyManager;
        this.config = config;
        this.clusters = storageFactory.create("elasticache", "elasticache-cache-clusters.json",
                new TypeReference<Map<String, CacheCluster>>() {});
    }

    public CacheCluster createCacheCluster(String clusterId) {
        if (clusters.get(clusterId).isPresent()) {
            throw new AwsException("CacheClusterAlreadyExistsFault",
                    "Cache cluster " + clusterId + " already exists.", 400);
        }

        String image = config.services().elasticache().defaultMemcachedImage();
        LOG.infov("Creating Memcached cluster {0} with image {1}", clusterId, image);

        ElastiCacheContainerHandle handle = null;
        int allocatedPort = -1;
        try {
            handle = containerManager.start(clusterId, image);
            String endpointHost = resolveEndpointHost(handle);
            RuntimeException lastProxyFailure = null;
            for (int attempt = 0; attempt < 25; attempt++) {
                int proxyPort = allocateProxyPort();
                allocatedPort = proxyPort;
                try {
                    Endpoint endpoint = new Endpoint(endpointHost, proxyPort);
                    CacheCluster cluster = new CacheCluster(
                            clusterId, CacheClusterStatus.AVAILABLE, ENGINE, ENGINE_VERSION,
                            endpoint, Instant.now());
                    cluster.setContainerId(handle.getContainerId());
                    cluster.setContainerHost(handle.getHost());
                    cluster.setContainerPort(handle.getPort());
                    cluster.setProxyPort(proxyPort);

                    proxyManager.startProxy(clusterId, proxyPort, handle.getHost(), handle.getPort());
                    clusters.put(clusterId, cluster);
                    LOG.infov("Memcached cluster {0} created, endpoint={1}:{2} authRequired={3}",
                            clusterId, endpointHost, String.valueOf(proxyPort), proxyManager.authRequired());
                    return cluster;
                } catch (RuntimeException e) {
                    releaseProxyPort(proxyPort);
                    allocatedPort = -1;
                    lastProxyFailure = e;
                    LOG.warnv("Failed to start Memcached proxy for cluster {0} on port {1} (attempt {2}): {3}",
                            clusterId, String.valueOf(proxyPort), attempt + 1, e.getMessage());
                }
            }
            if (lastProxyFailure != null) {
                throw lastProxyFailure;
            }
            throw new AwsException("InsufficientCacheClusterCapacity",
                    "No available proxy ports for cache cluster " + clusterId, 503);
        } catch (RuntimeException e) {
            rollback(clusterId, handle, allocatedPort);
            throw e;
        }
    }

    private void rollback(String clusterId, ElastiCacheContainerHandle handle, int proxyPort) {
        try {
            proxyManager.stopProxy(clusterId);
        } catch (RuntimeException e) {
            LOG.warnv("Error stopping Memcached proxy for cluster {0}: {1}", clusterId, e.getMessage());
        }
        try {
            if (handle != null) {
                containerManager.stop(handle);
            }
        } catch (RuntimeException e) {
            LOG.warnv("Error stopping Memcached container for cluster {0}: {1}", clusterId, e.getMessage());
        } finally {
            if (proxyPort >= 0) {
                releaseProxyPort(proxyPort);
            }
        }
    }

    public CacheCluster getCacheCluster(String clusterId) {
        return clusters.get(clusterId).orElseThrow(() ->
                new AwsException("CacheClusterNotFound",
                        "Cache cluster " + clusterId + " not found.", 404));
    }

    public Collection<CacheCluster> listCacheClusters(String filterClusterId) {
        if (filterClusterId != null && !filterClusterId.isBlank()) {
            return clusters.get(filterClusterId)
                    .map(List::of)
                    .orElseThrow(() -> new AwsException("CacheClusterNotFound",
                            "Cache cluster " + filterClusterId + " not found.", 404));
        }
        return clusters.scan(k -> true);
    }

    public CacheCluster deleteCacheCluster(String clusterId) {
        CacheCluster cluster = getCacheCluster(clusterId);

        cluster.setCacheClusterStatus(CacheClusterStatus.DELETING);
        clusters.put(clusterId, cluster);

        proxyManager.stopProxy(clusterId);

        if (cluster.getContainerId() != null) {
            containerManager.stop(new ElastiCacheContainerHandle(
                    cluster.getContainerId(), clusterId,
                    cluster.getContainerHost(), cluster.getContainerPort()));
        }

        if (cluster.getProxyPort() > 0) {
            releaseProxyPort(cluster.getProxyPort());
        }
        clusters.delete(clusterId);
        LOG.infov("Memcached cluster {0} deleted", clusterId);
        return cluster;
    }

    private String resolveEndpointHost(ElastiCacheContainerHandle handle) {
        return config.hostname().orElse(handle.getHost());
    }

    private int allocateProxyPort() {
        int base = config.services().elasticache().proxyBasePort();
        int max = config.services().elasticache().proxyMaxPort();
        Set<Integer> inUse = ConcurrentHashMap.newKeySet();
        inUse.addAll(usedPorts);
        for (CacheCluster cluster : clusters.scan(k -> true)) {
            if (cluster.getProxyPort() > 0) {
                inUse.add(cluster.getProxyPort());
            }
        }
        int port = PortAllocator.allocateFromRange(base, max, inUse, true);
        if (port < 0) {
            throw new AwsException("InsufficientCacheClusterCapacity",
                    "No available proxy ports in range " + base + "-" + max, 503);
        }
        usedPorts.add(port);
        return port;
    }

    private void releaseProxyPort(int port) {
        usedPorts.remove(port);
    }
}
