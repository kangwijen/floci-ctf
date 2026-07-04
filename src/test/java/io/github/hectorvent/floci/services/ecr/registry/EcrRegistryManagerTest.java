package io.github.hectorvent.floci.services.ecr.registry;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.CurrentContainerNetworkResolver;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.PortAllocator;
import com.github.dockerjava.api.model.Container;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import com.github.dockerjava.api.model.Container;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link EcrRegistryManager} startup behavior. Uses a real
 * {@link PortAllocator} and a mocked Docker layer so the failure path can be
 * exercised without a Docker daemon.
 */
class EcrRegistryManagerTest {

    private static final int BASE_PORT = 6100;
    private static final int MAX_PORT = 6101; // pool of exactly two ports
    private static final String REGISTRY_NAME = "floci-test-ecr-registry";

    private PortAllocator portAllocator;
    private ContainerLifecycleManager lifecycleManager;
    private ContainerDetector containerDetector;
    private CurrentContainerNetworkResolver currentContainerNetworkResolver;
    private EmulatorConfig.EcrServiceConfig ecrConfig;
    private EmulatorConfig config;
    private ContainerBuilder containerBuilder;
    private ContainerBuilder.Builder builder;
    private ContainerLogStreamer logStreamer;
    private RegionResolver regionResolver;
    private EcrRegistryManager manager;

    @BeforeEach
    void setUp() {
        portAllocator = new PortAllocator();

        containerBuilder = Mockito.mock(ContainerBuilder.class);
        builder = Mockito.mock(ContainerBuilder.Builder.class, Mockito.RETURNS_SELF);
        when(containerBuilder.newContainer(anyString())).thenReturn(builder);
        when(builder.build()).thenReturn(Mockito.mock(ContainerSpec.class));

        lifecycleManager = Mockito.mock(ContainerLifecycleManager.class);
        when(lifecycleManager.findByName(anyString())).thenReturn(Optional.empty());

        logStreamer = Mockito.mock(ContainerLogStreamer.class);
        containerDetector = Mockito.mock(ContainerDetector.class);
        currentContainerNetworkResolver = Mockito.mock(CurrentContainerNetworkResolver.class);
        regionResolver = new RegionResolver("us-east-1", "000000000000");

        config = Mockito.mock(EmulatorConfig.class);
        ecrConfig = Mockito.mock(EmulatorConfig.EcrServiceConfig.class);
        EmulatorConfig.StorageConfig storage = Mockito.mock(EmulatorConfig.StorageConfig.class);
        when(config.services()).thenReturn(Mockito.mock(EmulatorConfig.ServicesConfig.class));
        when(config.services().ecr()).thenReturn(ecrConfig);
        when(config.storage()).thenReturn(storage);
        // Empty host-persistent-path selects named-volume mode (no host bind-mount logic).
        when(storage.hostPersistentPath()).thenReturn("");
        when(ecrConfig.registryContainerName()).thenReturn(REGISTRY_NAME);
        when(ecrConfig.registryImage()).thenReturn("registry:2");
        when(ecrConfig.registryBasePort()).thenReturn(BASE_PORT);
        when(ecrConfig.registryMaxPort()).thenReturn(MAX_PORT);
        when(ecrConfig.dockerNetwork()).thenReturn(Optional.empty());
        when(ecrConfig.uriStyle()).thenReturn("hostname");
        when(ecrConfig.registryAuthEnabled()).thenReturn(false);
        EmulatorConfig.IamServiceConfig iamConfig = Mockito.mock(EmulatorConfig.IamServiceConfig.class);
        when(config.services().iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(false);

        manager = new EcrRegistryManager(containerBuilder, lifecycleManager, logStreamer,
                containerDetector, currentContainerNetworkResolver, portAllocator, config, regionResolver,
                Mockito.mock(EcrRegistryDataPlane.class));
    }

    @Test
    void ensureStarted_releasesPortWhenDockerStartFails_soPoolIsNotExhausted() {
        when(lifecycleManager.createAndStart(any()))
                .thenThrow(new RuntimeException("Cannot connect to the Docker daemon"));

        // Far more attempts than the two-port pool. Every attempt must surface the
        // real Docker failure. If the reserved port were leaked on failure, the pool
        // would exhaust after two attempts and later calls would instead fail with
        // "No free port available" — the symptom this test guards against.
        for (int attempt = 0; attempt < 6; attempt++) {
            RuntimeException ex = assertThrows(RuntimeException.class, manager::ensureStarted);
            assertTrue(ex.getMessage().contains("Failed to start ECR backing registry container"),
                    "attempt " + attempt + " should surface the Docker failure, got: " + ex.getMessage());
            assertFalse(ex.getMessage().contains("No free port available"),
                    "port pool leaked on attempt " + attempt + ": " + ex.getMessage());
        }
    }

    @Test
    void httpClient_usesRegistryContainerDnsWhenRunningInsideDockerBeforeStart() {
        when(containerDetector.isRunningInContainer()).thenReturn(true);

        assertEquals("http://" + REGISTRY_NAME + ":5000", manager.httpClient().baseUrl());
    }

    @Test
    void httpClient_usesLocalhostWhenRunningOnDockerHost() {
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        assertEquals("http://localhost:" + BASE_PORT, manager.httpClient().baseUrl());
    }

    @Test
    void internalRepoName_usesBareRepoForHostnameUriStyle() {
        assertEquals("floci-it/app", manager.internalRepoName("000000000000", "us-east-1", "floci-it/app"));
    }

    @Test
    void internalRepoName_usesAccountRegionPrefixForPathUriStyle() {
        when(ecrConfig.uriStyle()).thenReturn("path");

        assertEquals("000000000000/us-east-1/floci-it/app",
                manager.internalRepoName("000000000000", "us-east-1", "floci-it/app"));
    }

    @Test
    void ensureStarted_adoptExistingWithAuthProxy_resolvesInternalBackendPortOnNativeHost() {
        when(ecrConfig.registryAuthEnabled()).thenReturn(true);
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        Container existing = Mockito.mock(Container.class);
        when(existing.getId()).thenReturn("registry-existing-id");
        when(lifecycleManager.findByName(REGISTRY_NAME)).thenReturn(Optional.of(existing));
        when(lifecycleManager.resolveHostPublishedPort("registry-existing-id", 5000))
                .thenReturn(java.util.OptionalInt.of(51234));

        EcrRegistryDataPlane dataPlane = Mockito.mock(EcrRegistryDataPlane.class);
        manager = new EcrRegistryManager(containerBuilder, lifecycleManager, logStreamer,
                containerDetector, currentContainerNetworkResolver, portAllocator, config, regionResolver,
                dataPlane);

        manager.ensureStarted();

        ArgumentCaptor<String> backendUrlCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(dataPlane).start(Mockito.eq(BASE_PORT), backendUrlCaptor.capture());
        assertEquals("http://127.0.0.1:51234", backendUrlCaptor.getValue());
        assertTrue(manager.isStarted());
    }

    @Test
    void ensureStarted_usesGlobalDockerNetworkWhenEcrNetworkUnset() {
        when(config.services().dockerNetwork()).thenReturn(Optional.of("floci_default"));
        when(containerDetector.isRunningInContainer()).thenReturn(false);

        ArgumentCaptor<Optional<String>> networkCaptor = ArgumentCaptor.forClass(Optional.class);
        Mockito.doAnswer(inv -> builder).when(builder).withDockerNetwork(networkCaptor.capture());

        when(lifecycleManager.createAndStart(any()))
                .thenReturn(new ContainerLifecycleManager.ContainerInfo("new-registry", Map.of()));

        manager.ensureStarted();

        assertEquals(Optional.of("floci_default"), networkCaptor.getValue());
    }

    @Test
    void adoptUsesPublishedHostPortEvenWhenRunningInsideDocker() {
        // Regression: in container mode adopt()'s endpoint resolves to the registry's
        // internal port (5000); the advertised proxy endpoint must use the published
        // host binding instead, or docker login from the host daemon fails.
        when(containerDetector.isRunningInContainer()).thenReturn(true);
        Container existing = Mockito.mock(Container.class);
        when(existing.getId()).thenReturn("0123456789abcdef");
        when(lifecycleManager.findByName(REGISTRY_NAME)).thenReturn(Optional.of(existing));
        when(lifecycleManager.adopt("0123456789abcdef", List.of(5000)))
                .thenReturn(new ContainerLifecycleManager.ContainerInfo("0123456789abcdef",
                        Map.of(5000, new ContainerLifecycleManager.EndpointInfo("172.17.0.5", 5000)),
                        Map.of(5000, BASE_PORT + 1)));

        manager.ensureStarted();

        assertEquals(BASE_PORT + 1, manager.effectivePort());
        assertEquals("http://localhost:" + (BASE_PORT + 1), manager.getProxyEndpoint());
    }

    @Test
    void adoptKeepsConfiguredPortWhenNoPublishedBindingExists() {
        Container existing = Mockito.mock(Container.class);
        when(existing.getId()).thenReturn("0123456789abcdef");
        when(lifecycleManager.findByName(REGISTRY_NAME)).thenReturn(Optional.of(existing));
        when(lifecycleManager.adopt("0123456789abcdef", List.of(5000)))
                .thenReturn(new ContainerLifecycleManager.ContainerInfo("0123456789abcdef", Map.of()));

        manager.ensureStarted();

        assertEquals(BASE_PORT, manager.effectivePort());
    }
}
