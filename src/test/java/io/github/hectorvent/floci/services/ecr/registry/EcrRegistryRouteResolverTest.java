package io.github.hectorvent.floci.services.ecr.registry;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class EcrRegistryRouteResolverTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String REPO = "floci-it/app";

    private EmulatorConfig config;
    private EmulatorConfig.EcrServiceConfig ecrConfig;
    private EcrRegistryRouteResolver resolver;

    @BeforeEach
    void setUp() {
        config = Mockito.mock(EmulatorConfig.class);
        ecrConfig = Mockito.mock(EmulatorConfig.EcrServiceConfig.class);
        when(config.services()).thenReturn(Mockito.mock(EmulatorConfig.ServicesConfig.class));
        when(config.services().ecr()).thenReturn(ecrConfig);
        when(ecrConfig.uriStyle()).thenReturn("hostname");
        resolver = new EcrRegistryRouteResolver(config, new RegionResolver(REGION, ACCOUNT));
    }

    @Test
    void pingRouteDoesNotRequireAuth() {
        var route = resolver.resolve("GET", "/v2/", null, false).orElseThrow();
        assertEquals("/v2/", route.backendPath());
        assertFalse(route.requiresAuth());
    }

    @Test
    void hostnameStyleManifestMapsToBatchGetImage() {
        String host = ACCOUNT + ".dkr.ecr." + REGION + ".localhost:5100";
        var route = resolver.resolve("GET", "/v2/" + REPO + "/manifests/latest", host, false).orElseThrow();
        assertEquals("ecr:BatchGetImage", route.iamAction());
        assertEquals("arn:aws:ecr:" + REGION + ":" + ACCOUNT + ":repository/" + REPO, route.repositoryArn());
        assertEquals("/v2/" + REPO + "/manifests/latest", route.backendPath());
        assertTrue(route.requiresAuth());
    }

    @Test
    void pathStylePutManifestMapsToPutImage() {
        when(ecrConfig.uriStyle()).thenReturn("path");
        String path = "/v2/" + ACCOUNT + "/" + REGION + "/" + REPO + "/manifests/latest";
        var route = resolver.resolve("PUT", path, "localhost:5100", true).orElseThrow();
        assertEquals("ecr:PutImage", route.iamAction());
        assertEquals(path, route.backendPath());
    }

    @Test
    void blobUploadPatchMapsToUploadLayerPart() {
        String host = ACCOUNT + ".dkr.ecr." + REGION + ".localhost:5100";
        String path = "/v2/" + REPO + "/blobs/uploads/uuid";
        var route = resolver.resolve("PATCH", path, host, false).orElseThrow();
        assertEquals("ecr:UploadLayerPart", route.iamAction());
    }
}
