package io.github.hectorvent.floci.services.opensearch;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager.ContainerInfo;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.PortAllocator;
import io.github.hectorvent.floci.services.opensearch.model.Domain;
import io.github.hectorvent.floci.services.opensearch.proxy.OpenSearchDataPlane;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * E-FO-04: OpenSearch domain HTTP is published through the AuthProxy data plane,
 * not as an ungated container host bind.
 */
@Tag("security-regression")
class OpenSearchDomainAuthProxyBindTest {

    private OpenSearchDomainManager manager;
    private OpenSearchDataPlane dataPlane;
    private PortAllocator portAllocator;
    private ContainerBuilder containerBuilder;
    private ContainerBuilder.Builder specBuilder;

    @BeforeEach
    void setUp() {
        containerBuilder = mock(ContainerBuilder.class);
        specBuilder = mock(ContainerBuilder.Builder.class);
        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        ContainerDetector containerDetector = mock(ContainerDetector.class);
        portAllocator = mock(PortAllocator.class);
        dataPlane = mock(OpenSearchDataPlane.class);
        EmulatorConfig config = mock(EmulatorConfig.class);

        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.OpenSearchServiceConfig osConfig = mock(EmulatorConfig.OpenSearchServiceConfig.class);
        EmulatorConfig.StorageConfig storage = mock(EmulatorConfig.StorageConfig.class);
        when(config.services()).thenReturn(services);
        when(services.opensearch()).thenReturn(osConfig);
        when(services.dockerNetwork()).thenReturn(Optional.empty());
        when(osConfig.proxyBasePort()).thenReturn(9400);
        when(osConfig.proxyMaxPort()).thenReturn(9499);
        when(osConfig.defaultImage()).thenReturn(Optional.empty());
        when(config.storage()).thenReturn(storage);
        when(storage.persistentPath()).thenReturn("/tmp/floci");
        when(storage.hostPersistentPath()).thenReturn("/tmp/floci");
        when(storage.mode()).thenReturn("memory");

        when(portAllocator.allocate(9400, 9499)).thenReturn(9400);
        when(containerDetector.isRunningInContainer()).thenReturn(false);
        when(containerBuilder.newContainer(anyString())).thenReturn(specBuilder);
        when(specBuilder.withName(anyString())).thenReturn(specBuilder);
        when(specBuilder.withEnv(anyString(), anyString())).thenReturn(specBuilder);
        when(specBuilder.withDynamicPort(anyInt())).thenReturn(specBuilder);
        when(specBuilder.withExposedPort(anyInt())).thenReturn(specBuilder);
        when(specBuilder.withDockerNetwork(any())).thenReturn(specBuilder);
        when(specBuilder.withLogRotation()).thenReturn(specBuilder);
        when(specBuilder.withBind(anyString(), anyString())).thenReturn(specBuilder);
        when(specBuilder.build()).thenReturn(mock(ContainerSpec.class));

        ContainerInfo info = mock(ContainerInfo.class);
        when(info.containerId()).thenReturn("cid");
        when(info.getEndpoint(9200)).thenReturn(
                new ContainerLifecycleManager.EndpointInfo("127.0.0.1", 32700));
        when(lifecycleManager.createAndStart(any())).thenReturn(info);

        manager = new OpenSearchDomainManager(
                containerBuilder, lifecycleManager, containerDetector,
                portAllocator, config, dataPlane);
    }

    @Test
    void startDomain_bindsDataPlaneAuthProxyAndUsesProxyEndpoint() {
        Domain domain = new Domain();
        domain.setDomainName("search-a");
        domain.setEngineVersion("OpenSearch_2.19");
        domain.setVolumeId("abc123");
        domain.setArn("arn:aws:es:us-east-1:000000000000:domain/search-a");

        manager.startDomain(domain);

        assertEquals("http://localhost:9400", domain.getEndpoint());
        verify(specBuilder).withDynamicPort(9200);
        verify(dataPlane).start(eq("search-a"), eq(9400), eq("http://127.0.0.1:32700"),
                eq(domain.getArn()), any());
    }
}
