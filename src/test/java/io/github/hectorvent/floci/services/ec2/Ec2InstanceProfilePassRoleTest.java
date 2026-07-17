package io.github.hectorvent.floci.services.ec2;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ec2.model.Instance;
import io.github.hectorvent.floci.services.ec2.model.Reservation;
import io.github.hectorvent.floci.services.ec2.portforward.Ec2PortForwardManager;
import io.github.hectorvent.floci.services.iam.ComputePassRoleGate;
import jakarta.enterprise.event.Event;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * O1: EC2 RunInstances with an instance profile must require iam:PassRole on attached roles.
 */
@Tag("security-regression")
class Ec2InstanceProfilePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String PROFILE_ARN =
            "arn:aws:iam::000000000000:instance-profile/my-profile";

    private ComputePassRoleGate passRoleGate;
    private Ec2Service service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.Ec2ServiceConfig ec2 = mock(EmulatorConfig.Ec2ServiceConfig.class);
        when(config.defaultAccountId()).thenReturn("000000000000");
        when(config.services()).thenReturn(services);
        when(services.ec2()).thenReturn(ec2);
        when(ec2.mock()).thenReturn(true);

        passRoleGate = mock(ComputePassRoleGate.class);
        service = new Ec2Service(
                config,
                mock(Ec2ContainerManager.class),
                mock(Ec2PortForwardManager.class),
                mock(AmiImageResolver.class),
                mock(Ec2ImageCatalog.class),
                new Ec2InstanceTypeCatalog(),
                new InMemoryStorageFactory(),
                mock(Event.class),
                passRoleGate);
    }

    @Test
    void runInstancesRequiresPassRoleForInstanceProfile() {
        Reservation reservation = service.runInstances(
                REGION, "ami-12345678", "t2.micro", 1, 1, null, List.of(), null,
                null, List.of(), null, PROFILE_ARN);

        verify(passRoleGate).authorizeEc2InstanceProfile(PROFILE_ARN, REGION);
        Instance inst = reservation.getInstances().getFirst();
        assertEquals(PROFILE_ARN, inst.getIamInstanceProfileArn());
    }

    @Test
    void runInstancesDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeEc2InstanceProfile(eq(PROFILE_ARN), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.runInstances(
                        REGION, "ami-12345678", "t2.micro", 1, 1, null, List.of(), null,
                        null, List.of(), null, PROFILE_ARN));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    private static final class InMemoryStorageFactory extends StorageFactory {
        private InMemoryStorageFactory() {
            super(null, null);
        }

        @Override
        public <V> StorageBackend<String, V> create(String serviceName, String fileName,
                                                    TypeReference<Map<String, V>> typeReference) {
            return new InMemoryStorage<>();
        }
    }
}
