package io.github.hectorvent.floci.services.docdb;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.docdb.container.DocDbContainerHandle;
import io.github.hectorvent.floci.services.docdb.container.DocDbContainerManager;
import io.github.hectorvent.floci.services.docdb.model.DocDbCluster;
import io.github.hectorvent.floci.services.docdb.proxy.DocDbProxyManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * E-FO-03: DocumentDB publishes the AuthProxy port, not the raw Mongo container port.
 */
@Tag("security-regression")
class DocDbAuthProxyBindTest {

    private DocDbService service;
    private DocDbProxyManager proxyManager;

    @BeforeEach
    void setUp() {
        DocDbContainerManager containerManager = mock(DocDbContainerManager.class);
        proxyManager = mock(DocDbProxyManager.class);
        StorageFactory storageFactory = mock(StorageFactory.class);
        EmulatorConfig config = mock(EmulatorConfig.class);
        RegionResolver regionResolver = new RegionResolver("us-east-1", "000000000000");

        EmulatorConfig.ServicesConfig servicesConfig = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.DocDbServiceConfig docdbConfig = mock(EmulatorConfig.DocDbServiceConfig.class);
        when(config.services()).thenReturn(servicesConfig);
        when(servicesConfig.docdb()).thenReturn(docdbConfig);
        when(docdbConfig.mock()).thenReturn(false);
        when(docdbConfig.defaultImage()).thenReturn("mongo:7.0");
        when(docdbConfig.proxyBasePort()).thenReturn(27018);
        when(docdbConfig.proxyMaxPort()).thenReturn(27099);
        when(config.hostname()).thenReturn(Optional.of("localhost"));

        when(storageFactory.create(anyString(), anyString(), any()))
                .thenAnswer(inv -> new InMemoryStorage<>());
        when(containerManager.start(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new DocDbContainerHandle("cid", "cluster-a", "127.0.0.1", 32768));
        doNothing().when(proxyManager).startProxy(
                anyString(), anyBoolean(), anyInt(), anyString(), anyInt(),
                anyString(), anyString());

        service = new DocDbService(config, regionResolver, containerManager, proxyManager, storageFactory);
    }

    @Test
    void createClusterWithIamAuth_bindsAuthProxyNotRawContainerPort() {
        DocDbCluster cluster = service.createDbCluster(
                "cluster-a", "5.0.0", "admin", "secret99", true);

        assertEquals("localhost", cluster.getEndpoint());
        assertEquals(27018, cluster.getPort());
        assertEquals(32768, cluster.getContainerPort());
        assertNotEquals(cluster.getContainerPort(), cluster.getPort());
        assertTrue(cluster.getProxyPort() > 0);
        assertEquals(cluster.getProxyPort(), cluster.getPort());

        verify(proxyManager).startProxy(
                eq("cluster-a"),
                eq(true),
                eq(27018),
                eq("127.0.0.1"),
                eq(32768),
                eq("admin"),
                eq("secret99"));
    }

    @Test
    void createClusterWithoutIam_stillBindsAuthProxy() {
        DocDbCluster cluster = service.createDbCluster(
                "cluster-b", null, "admin", "secret99", false);

        assertEquals(27018, cluster.getPort());
        assertNotEquals(cluster.getContainerPort(), cluster.getPort());
        verify(proxyManager).startProxy(
                eq("cluster-b"),
                eq(false),
                eq(27018),
                eq("127.0.0.1"),
                eq(32768),
                eq("admin"),
                eq("secret99"));
    }
}
