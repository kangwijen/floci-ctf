package io.github.hectorvent.floci.services.opensearch;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager.ContainerInfo;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.ContainerStorageHelper;
import io.github.hectorvent.floci.core.common.docker.PortAllocator;
import io.github.hectorvent.floci.services.opensearch.model.Domain;
import io.github.hectorvent.floci.services.opensearch.proxy.OpenSearchDataPlane;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.file.Path;

/**
 * Manages the Docker lifecycle of OpenSearch containers for real-mode domains.
 * Host HTTP is published through {@link OpenSearchDataPlane} (AuthProxy), not as an
 * ungated container port bind.
 */
@ApplicationScoped
public class OpenSearchDomainManager {

    private static final Logger LOG = Logger.getLogger(OpenSearchDomainManager.class);
    private static final int OPENSEARCH_PORT = 9200;

    private final ContainerBuilder containerBuilder;
    private final ContainerLifecycleManager lifecycleManager;
    private final ContainerDetector containerDetector;
    private final PortAllocator portAllocator;
    private final EmulatorConfig config;
    private final OpenSearchDataPlane dataPlane;

    @Inject
    public OpenSearchDomainManager(ContainerBuilder containerBuilder,
                                   ContainerLifecycleManager lifecycleManager,
                                   ContainerDetector containerDetector,
                                   PortAllocator portAllocator,
                                   EmulatorConfig config,
                                   OpenSearchDataPlane dataPlane) {
        this.containerBuilder = containerBuilder;
        this.lifecycleManager = lifecycleManager;
        this.containerDetector = containerDetector;
        this.portAllocator = portAllocator;
        this.config = config;
        this.dataPlane = dataPlane;
    }

    public void startDomain(Domain domain) {
        String image = resolveImage(domain.getEngineVersion());
        String containerName = containerName(domain);

        LOG.infov("Starting OpenSearch container for domain: {0} (version={1}, image={2})",
                domain.getDomainName(), domain.getEngineVersion(), image);

        int hostPort = portAllocator.allocate(
                config.services().opensearch().proxyBasePort(),
                config.services().opensearch().proxyMaxPort());

        lifecycleManager.removeIfExists(containerName);

        ContainerBuilder.Builder specBuilder = containerBuilder.newContainer(image)
                .withName(containerName)
                .withEnv("discovery.type", "single-node")
                .withDockerNetwork(config.services().dockerNetwork())
                .withLogRotation();

        if (!containerDetector.isRunningInContainer()) {
            specBuilder.withDynamicPort(OPENSEARCH_PORT);
        } else {
            specBuilder.withExposedPort(OPENSEARCH_PORT);
        }

        applyEngineEnv(specBuilder, domain.getEngineVersion());

        if (ContainerStorageHelper.isNamedVolumeMode(config)) {
            ContainerStorageHelper.applyStorage(specBuilder, lifecycleManager, config,
                    "opensearch", domain.getVolumeId(), domain.getDomainName(),
                    "/usr/share/opensearch/data");
        } else {
            Path dataPath = ContainerStorageHelper.hostResourcePath(config, "opensearch", domain.getDomainName());
            if (!containerDetector.isRunningInContainer()) {
                ContainerStorageHelper.ensureHostDir(dataPath.toString());
            }
            String dataPathStr = dataPath.toAbsolutePath().normalize().toString();
            String persistentPathStr = Path.of(config.storage().persistentPath()).toAbsolutePath().normalize().toString();
            String hostDataPath = dataPathStr.replace(persistentPathStr, config.storage().hostPersistentPath());
            specBuilder.withBind(hostDataPath, "/usr/share/opensearch/data");
        }

        ContainerSpec spec = specBuilder.build();

        ContainerInfo info = lifecycleManager.createAndStart(spec);
        domain.setContainerId(info.containerId());

        var endpoint = info.getEndpoint(OPENSEARCH_PORT);
        String backendBaseUrl = "http://" + endpoint.host() + ":" + endpoint.port();
        if (containerDetector.isRunningInContainer()) {
            backendBaseUrl = "http://" + containerName + ":" + OPENSEARCH_PORT;
        }

        dataPlane.start(domain.getDomainName(), hostPort, backendBaseUrl,
                domain.getArn(), domain.getAdvancedSecurityOptions());

        if (containerDetector.isRunningInContainer()) {
            domain.setEndpoint("http://" + containerName + ":" + hostPort);
        } else {
            domain.setEndpoint("http://localhost:" + hostPort);
        }

        LOG.infov("OpenSearch AuthProxy for domain {0} on port {1} → {2}",
                domain.getDomainName(), String.valueOf(hostPort), backendBaseUrl);
    }

    public boolean isReady(Domain domain) {
        String containerName = containerName(domain);
        String url = "http://" + containerName + ":" + OPENSEARCH_PORT + "/_cluster/health";
        try {
            HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setConnectTimeout(2000);
            conn.setReadTimeout(2000);
            int code = conn.getResponseCode();
            if (code == 200) {
                String body = new String(conn.getInputStream().readAllBytes());
                boolean ready = body.contains("\"green\"") || body.contains("\"yellow\"");
                if (ready) {
                    LOG.infov("OpenSearch domain {0} is ready (internal check)", domain.getDomainName());
                }
                return ready;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    public void stopDomain(Domain domain) {
        if (domain.getContainerId() == null) {
            return;
        }
        dataPlane.stop(domain.getDomainName());
        if (config.services().opensearch().keepRunningOnShutdown()) {
            LOG.infov("Leaving OpenSearch container for domain {0} running", domain.getDomainName());
            return;
        }
        lifecycleManager.stopAndRemove(domain.getContainerId(), null);
        LOG.infov("Stopped OpenSearch container for domain {0}", domain.getDomainName());
    }

    public void removeDomainStorage(Domain domain) {
        ContainerStorageHelper.removeStorage(config, lifecycleManager,
                "opensearch", domain.getVolumeId(), domain.getDomainName());
    }

    private String resolveImage(String engineVersion) {
        return OpenSearchVersions.resolveImage(
                config.services().opensearch().defaultImage(), engineVersion);
    }

    private String containerName(Domain domain) {
        return ContainerStorageHelper.resourceName(config, "opensearch", null, domain.getDomainName());
    }

    private void applyEngineEnv(ContainerBuilder.Builder specBuilder, String engineVersion) {
        if (engineVersion != null && engineVersion.startsWith("Elasticsearch")) {
            return;
        }
        specBuilder.withEnv("DISABLE_SECURITY_PLUGIN", "true");
        if (requiresInitialAdminPassword(engineVersion)) {
            specBuilder.withEnv("OPENSEARCH_INITIAL_ADMIN_PASSWORD", "FlociAdmin1!");
        }
    }

    private boolean requiresInitialAdminPassword(String engineVersion) {
        if (engineVersion == null || !engineVersion.startsWith("OpenSearch_")) {
            return false;
        }
        String numeric = engineVersion.substring("OpenSearch_".length());
        int dot = numeric.indexOf('.');
        if (dot < 0) {
            return false;
        }
        try {
            int major = Integer.parseInt(numeric.substring(0, dot));
            int minor = Integer.parseInt(numeric.substring(dot + 1));
            return major > 2 || (major == 2 && minor >= 12);
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
