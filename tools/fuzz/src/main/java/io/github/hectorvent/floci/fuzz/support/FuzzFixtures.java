package io.github.hectorvent.floci.fuzz.support;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.ResolvedServiceCatalog;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryRouteResolver;
import io.github.hectorvent.floci.services.elasticache.proxy.SigV4Validator;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.services.rds.proxy.RdsSigV4Validator;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.mockito.Mockito;

import java.lang.reflect.Constructor;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * CDI-free fixtures for fuzz targets.
 */
public final class FuzzFixtures {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private FuzzFixtures() {
    }

    public static ObjectMapper objectMapper() {
        return MAPPER;
    }

    public static ResourceArnBuilder resourceArnBuilder() {
        return new ResourceArnBuilder(MAPPER, null);
    }

    public static IamActionRegistry iamActionRegistry() {
        ResolvedServiceCatalog catalog = Mockito.mock(ResolvedServiceCatalog.class);
        when(catalog.matchTarget(anyString())).thenReturn(Optional.empty());
        return new IamActionRegistry(catalog);
    }

    public static IamActionRegistry iamActionRegistry(ResolvedServiceCatalog catalog) {
        return new IamActionRegistry(catalog);
    }

    public static EcrRegistryRouteResolver ecrRegistryRouteResolver() {
        return ecrRegistryRouteResolver("hostname");
    }

    public static EcrRegistryRouteResolver ecrRegistryRouteResolver(String uriStyle) {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class);
        EmulatorConfig.EcrServiceConfig ecrConfig = Mockito.mock(EmulatorConfig.EcrServiceConfig.class);
        when(config.services()).thenReturn(Mockito.mock(EmulatorConfig.ServicesConfig.class));
        when(config.services().ecr()).thenReturn(ecrConfig);
        when(ecrConfig.uriStyle()).thenReturn(uriStyle);
        return new EcrRegistryRouteResolver(config, new RegionResolver("us-east-1", "000000000000"));
    }

    public static IamService iamServiceWithAccessKey(String accessKeyId, String secretAccessKey) {
        try {
            Constructor<IamService> constructor = IamService.class.getDeclaredConstructor(
                    StorageBackend.class,
                    StorageBackend.class,
                    StorageBackend.class,
                    StorageBackend.class,
                    StorageBackend.class,
                    StorageBackend.class,
                    StorageBackend.class,
                    RegionResolver.class);
            constructor.setAccessible(true);

            InMemoryStorage<String, AccessKey> accessKeys = new InMemoryStorage<>();
            accessKeys.put(accessKeyId, new AccessKey(accessKeyId, secretAccessKey, "fuzz-user"));

            return constructor.newInstance(
                    null,
                    null,
                    null,
                    null,
                    accessKeys,
                    null,
                    null,
                    new RegionResolver("us-east-1", "123456789012"));
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to construct IamService fuzz fixture", e);
        }
    }

    public static SigV4Validator elasticacheSigV4Validator(IamService iamService) {
        return new SigV4Validator(iamService, authConfigWithoutRoot());
    }

    public static RdsSigV4Validator rdsSigV4Validator(IamService iamService) {
        return new RdsSigV4Validator(iamService, authConfigWithoutRoot());
    }

    private static EmulatorConfig authConfigWithoutRoot() {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class);
        EmulatorConfig.AuthConfig authConfig = Mockito.mock(EmulatorConfig.AuthConfig.class);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        return config;
    }
}
