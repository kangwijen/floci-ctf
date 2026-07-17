package io.github.hectorvent.floci.services.ecs;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ecs.container.EcsContainerManager;
import io.github.hectorvent.floci.services.ecs.model.ContainerDefinition;
import io.github.hectorvent.floci.services.ecs.model.LaunchType;
import io.github.hectorvent.floci.services.ecs.model.NetworkMode;
import io.github.hectorvent.floci.services.iam.ComputePassRoleGate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * O1: ECS RegisterTaskDefinition / RunTask must require iam:PassRole on task and execution roles.
 */
@Tag("security-regression")
class EcsTaskRoleRequiresPassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String TASK_ROLE = "arn:aws:iam::000000000000:role/ecs-task";
    private static final String EXEC_ROLE = "arn:aws:iam::000000000000:role/ecs-exec";

    private ComputePassRoleGate passRoleGate;
    private EcsService service;

    @BeforeEach
    void setUp() {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecs().mock()).thenReturn(true);
        when(config.effectiveBaseUrl()).thenReturn("http://localhost:4566");
        passRoleGate = mock(ComputePassRoleGate.class);
        service = new EcsService(
                new RegionResolver(REGION, "000000000000"),
                mock(EcsContainerManager.class),
                config,
                mock(EcsLoadBalancerRegistrar.class),
                new SingleUseStorageFactory(),
                passRoleGate);
        service.initializeStorage();
    }

    @Test
    void registerTaskDefinitionRequiresPassRoleOnBothRoles() {
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");

        service.registerTaskDefinition("passrole-fam", List.of(cd), NetworkMode.bridge,
                null, null, TASK_ROLE, EXEC_ROLE, List.of(), REGION);

        verify(passRoleGate).authorizeEcsTaskRoles(TASK_ROLE, EXEC_ROLE, REGION);
    }

    @Test
    void registerTaskDefinitionDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeEcsTaskRoles(eq(TASK_ROLE), eq(EXEC_ROLE), eq(REGION));

        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");

        AwsException ex = assertThrows(AwsException.class,
                () -> service.registerTaskDefinition("denied-fam", List.of(cd), NetworkMode.bridge,
                        null, null, TASK_ROLE, EXEC_ROLE, List.of(), REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void runTaskRequiresPassRoleOnTaskDefinitionRoles() {
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");
        service.registerTaskDefinition("run-fam", List.of(cd), NetworkMode.bridge,
                null, null, TASK_ROLE, EXEC_ROLE, List.of(), REGION);

        service.runTask(null, "run-fam", 1, LaunchType.EC2, null, null, List.of(), null, REGION);

        verify(passRoleGate, times(2)).authorizeEcsTaskRoles(TASK_ROLE, EXEC_ROLE, REGION);
    }

    @Test
    void runTaskDeniesWhenPassRoleDeniedAtLaunch() {
        ContainerDefinition cd = new ContainerDefinition();
        cd.setName("app");
        cd.setImage("nginx:alpine");
        service.registerTaskDefinition("run-deny-fam", List.of(cd), NetworkMode.bridge,
                null, null, TASK_ROLE, EXEC_ROLE, List.of(), REGION);

        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeEcsTaskRoles(eq(TASK_ROLE), eq(EXEC_ROLE), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.runTask(null, "run-deny-fam", 1, LaunchType.EC2, null, null,
                        List.of(), null, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    private static final class SingleUseStorageFactory extends StorageFactory {
        private final Map<String, StorageBackend<String, ?>> stores = new HashMap<>();

        private SingleUseStorageFactory() {
            super(null, null);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <V> StorageBackend<String, V> create(String serviceName,
                                                    String fileName,
                                                    TypeReference<Map<String, V>> typeReference) {
            return (StorageBackend<String, V>) stores.computeIfAbsent(fileName, ignored -> new InMemoryStorage<>());
        }
    }
}
