package io.github.hectorvent.floci.services.docdb;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.port.PortAllocator;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.docdb.container.DocDbContainerHandle;
import io.github.hectorvent.floci.services.docdb.container.DocDbContainerManager;
import io.github.hectorvent.floci.services.docdb.model.DocDbCluster;
import io.github.hectorvent.floci.services.docdb.model.DocDbInstance;
import io.github.hectorvent.floci.services.docdb.proxy.DocDbProxyManager;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class DocDbService {

    private static final Logger LOG = Logger.getLogger(DocDbService.class);
    private static final String ENGINE_VERSION_DEFAULT = "5.0.0";
    private static final int MONGO_PORT = 27017;

    private final StorageBackend<String, DocDbCluster> clusters;
    private final StorageBackend<String, DocDbInstance> instances;
    private final EmulatorConfig config;
    private final RegionResolver regionResolver;
    private final DocDbContainerManager containerManager;
    private final DocDbProxyManager proxyManager;
    private final Set<Integer> usedPorts = ConcurrentHashMap.newKeySet();

    @Inject
    public DocDbService(EmulatorConfig config,
                        RegionResolver regionResolver,
                        DocDbContainerManager containerManager,
                        DocDbProxyManager proxyManager,
                        StorageFactory storageFactory) {
        this.config = config;
        this.regionResolver = regionResolver;
        this.containerManager = containerManager;
        this.proxyManager = proxyManager;
        this.clusters = storageFactory.create("docdb", "docdb-clusters.json",
                new TypeReference<Map<String, DocDbCluster>>() {});
        this.instances = storageFactory.create("docdb", "docdb-instances.json",
                new TypeReference<Map<String, DocDbInstance>>() {});
    }

    // ── Clusters ──────────────────────────────────────────────────────────────

    public DocDbCluster createDbCluster(String id, String engineVersion,
                                        String masterUsername, String masterPassword,
                                        boolean iamEnabled) {
        if (clusters.get(id).isPresent()) {
            throw new AwsException("DBClusterAlreadyExistsFault",
                    "DocDB cluster " + id + " already exists.", 400);
        }

        String region = regionResolver.getDefaultRegion();

        DocDbCluster cluster = new DocDbCluster();
        cluster.setDbClusterIdentifier(id);
        cluster.setStatus("available");
        cluster.setEngineVersion(engineVersion != null ? engineVersion : ENGINE_VERSION_DEFAULT);
        cluster.setMasterUsername(masterUsername);
        cluster.setMasterPassword(masterPassword);
        cluster.setIamDatabaseAuthenticationEnabled(iamEnabled);
        cluster.setDbClusterArn(regionResolver.buildArn("rds", region, "cluster:" + id));
        cluster.setDbClusterResourceId("cluster-" + UUID.randomUUID().toString()
                .replace("-", "").substring(0, 24).toUpperCase());
        cluster.setCreatedAt(Instant.now());
        cluster.setDbClusterMembers(new ArrayList<>());

        if (config.services().docdb().mock()) {
            LOG.infov("Creating DocDB cluster {0} in mock mode (no container)", id);
            cluster.setEndpoint("localhost");
            cluster.setReaderEndpoint("localhost");
            cluster.setPort(MONGO_PORT);
        } else {
            DocDbContainerHandle handle = null;
            int proxyPort = -1;
            boolean provisioned = false;
            try {
                String image = config.services().docdb().defaultImage();
                proxyPort = allocateProxyPort();
                String endpointHost = resolveEndpointHost();
                LOG.infov("Creating DocDB cluster {0} on AuthProxy port {1}, image={2}",
                        id, String.valueOf(proxyPort), image);
                handle = containerManager.start(id, image, masterUsername, masterPassword);

                cluster.setEndpoint(endpointHost);
                cluster.setReaderEndpoint(endpointHost);
                cluster.setPort(proxyPort);
                cluster.setProxyPort(proxyPort);
                cluster.setContainerId(handle.getContainerId());
                cluster.setContainerHost(handle.getHost());
                cluster.setContainerPort(handle.getPort());

                proxyManager.startProxy(id, iamEnabled, proxyPort,
                        handle.getHost(), handle.getPort(),
                        masterUsername, masterPassword);

                clusters.put(id, cluster);
                provisioned = true;
                LOG.infov("DocDB cluster {0} created, endpoint={1}:{2}",
                        id, endpointHost, String.valueOf(proxyPort));
                return cluster;
            } catch (RuntimeException e) {
                LOG.warnv("DocDB cluster {0} provisioning failed, rolling back: {1}",
                        id, e.getMessage());
                throw e;
            } finally {
                if (!provisioned) {
                    rollbackDbCluster(id, handle, proxyPort);
                }
            }
        }

        clusters.put(id, cluster);
        LOG.infov("DocDB cluster {0} created, endpoint={1}:{2}",
                id, cluster.getEndpoint(), String.valueOf(cluster.getPort()));
        return cluster;
    }

    private void rollbackDbCluster(String id, DocDbContainerHandle handle, int proxyPort) {
        try {
            try {
                if (handle != null) {
                    proxyManager.stopProxy(id);
                }
            } catch (RuntimeException e) {
                LOG.warnv("Error stopping AuthProxy for DocDB cluster {0}: {1}", id, e.getMessage());
            }
            try {
                if (handle != null) {
                    containerManager.stop(handle);
                }
            } catch (RuntimeException e) {
                LOG.warnv("Error stopping container for DocDB cluster {0}: {1}", id, e.getMessage());
            }
        } finally {
            if (proxyPort >= 0) {
                releaseProxyPort(proxyPort);
            }
        }
    }

    public DocDbCluster getDbCluster(String id) {
        return clusters.get(id).orElseThrow(() ->
                new AwsException("DBClusterNotFoundFault",
                        "DocDB cluster " + id + " not found.", 404));
    }

    public boolean hasCluster(String id) {
        if (id == null || id.isBlank()) {
            return false;
        }
        return clusters.get(id).isPresent();
    }

    public boolean hasInstance(String id) {
        if (id == null || id.isBlank()) {
            return false;
        }
        return instances.get(id).isPresent();
    }

    public Collection<DocDbCluster> listDbClusters(String filterId) {
        if (filterId != null && !filterId.isBlank()) {
            return clusters.scan(k -> k.equalsIgnoreCase(filterId));
        }
        return clusters.scan(k -> true);
    }

    public DocDbCluster modifyDbCluster(String id, String engineVersion, Boolean iamEnabled) {
        DocDbCluster cluster = getDbCluster(id);
        if (engineVersion != null && !engineVersion.isBlank()) {
            cluster.setEngineVersion(engineVersion);
        }
        if (iamEnabled != null) {
            cluster.setIamDatabaseAuthenticationEnabled(iamEnabled);
        }
        clusters.put(id, cluster);
        LOG.infov("DocDB cluster {0} modified", id);
        return cluster;
    }

    public void deleteDbCluster(String id) {
        DocDbCluster cluster = clusters.get(id).orElseThrow(() ->
                new AwsException("DBClusterNotFoundFault",
                        "DocDB cluster " + id + " not found.", 404));

        if (cluster.getDbClusterMembers() != null && !cluster.getDbClusterMembers().isEmpty()) {
            throw new AwsException("InvalidDBClusterStateFault",
                    "Cannot delete DocDB cluster " + id + " — it still has DB instances.", 400);
        }

        cluster.setStatus("deleting");
        clusters.put(id, cluster);

        proxyManager.stopProxy(id);

        if (cluster.getContainerId() != null) {
            containerManager.stop(new DocDbContainerHandle(
                    cluster.getContainerId(), id,
                    cluster.getContainerHost(), cluster.getContainerPort()));
        }

        releaseProxyPort(cluster.getProxyPort());
        clusters.delete(id);
        LOG.infov("DocDB cluster {0} deleted", id);
    }

    // ── Instances ─────────────────────────────────────────────────────────────

    public DocDbInstance createDbInstance(String id, String dbClusterIdentifier,
                                          String dbInstanceClass, String engineVersion,
                                          boolean iamEnabled) {
        if (instances.get(id).isPresent()) {
            throw new AwsException("DBInstanceAlreadyExists",
                    "DocDB instance " + id + " already exists.", 400);
        }

        DocDbCluster cluster = getDbCluster(dbClusterIdentifier);
        String region = regionResolver.getDefaultRegion();

        DocDbInstance instance = new DocDbInstance();
        instance.setDbInstanceIdentifier(id);
        instance.setDbClusterIdentifier(dbClusterIdentifier);
        instance.setDbInstanceClass(dbInstanceClass != null ? dbInstanceClass : "db.r5.large");
        instance.setEngineVersion(engineVersion != null ? engineVersion : cluster.getEngineVersion());
        instance.setStatus("available");
        instance.setEndpoint(cluster.getEndpoint());
        instance.setPort(cluster.getPort());
        instance.setIamDatabaseAuthenticationEnabled(iamEnabled);
        instance.setDbInstanceArn(regionResolver.buildArn("rds", region, "db:" + id));
        instance.setDbiResourceId("db-" + UUID.randomUUID().toString()
                .replace("-", "").substring(0, 24).toUpperCase());
        instance.setCreatedAt(Instant.now());

        cluster.getDbClusterMembers().add(id);
        clusters.put(dbClusterIdentifier, cluster);

        instances.put(id, instance);
        LOG.infov("DocDB instance {0} created in cluster {1}", id, dbClusterIdentifier);
        return instance;
    }

    public DocDbInstance getDbInstance(String id) {
        return instances.get(id).orElseThrow(() ->
                new AwsException("DBInstanceNotFound",
                        "DocDB instance " + id + " not found.", 404));
    }

    public Collection<DocDbInstance> listDbInstances(String filterId) {
        if (filterId != null && !filterId.isBlank()) {
            return instances.scan(k -> k.equalsIgnoreCase(filterId));
        }
        return instances.scan(k -> true);
    }

    public DocDbInstance modifyDbInstance(String id, String dbInstanceClass, Boolean iamEnabled) {
        DocDbInstance instance = getDbInstance(id);
        if (dbInstanceClass != null && !dbInstanceClass.isBlank()) {
            instance.setDbInstanceClass(dbInstanceClass);
        }
        if (iamEnabled != null) {
            instance.setIamDatabaseAuthenticationEnabled(iamEnabled);
        }
        instances.put(id, instance);
        LOG.infov("DocDB instance {0} modified", id);
        return instance;
    }

    public void deleteDbInstance(String id) {
        DocDbInstance instance = instances.get(id).orElseThrow(() ->
                new AwsException("DBInstanceNotFound",
                        "DocDB instance " + id + " not found.", 404));

        String clusterId = instance.getDbClusterIdentifier();
        DocDbCluster cluster = clusters.get(clusterId).orElse(null);
        if (cluster != null) {
            cluster.getDbClusterMembers().remove(id);
            clusters.put(clusterId, cluster);
        }

        instances.delete(id);
        LOG.infov("DocDB instance {0} deleted", id);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String resolveEndpointHost() {
        return config.hostname().orElse("localhost");
    }

    private int allocateProxyPort() {
        int base = config.services().docdb().proxyBasePort();
        int max = config.services().docdb().proxyMaxPort();
        int port = PortAllocator.allocateFromRange(base, max, usedPorts, true);
        if (port < 0) {
            throw new AwsException("InsufficientDBClusterCapacityFault",
                    "No available DocDB AuthProxy ports in range " + base + "-" + max, 503);
        }
        return port;
    }

    private void releaseProxyPort(int port) {
        if (port > 0) {
            usedPorts.remove(port);
        }
    }
}
