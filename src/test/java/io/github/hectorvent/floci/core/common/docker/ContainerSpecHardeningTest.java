package io.github.hectorvent.floci.core.common.docker;

import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.Mount;
import com.github.dockerjava.api.model.MountType;
import com.github.dockerjava.api.model.Volume;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("security-regression")
class ContainerSpecHardeningTest {

    @Test
    void rejectsPrivilegedForNonOperatorSpec() {
        ContainerSpec spec = new ContainerSpec(
                "busybox:latest",
                null,
                List.of(),
                null,
                null,
                null,
                java.util.Map.of(),
                List.of(),
                null,
                List.of(),
                List.of(),
                List.of(),
                null,
                true,
                null,
                List.of(),
                null,
                null,
                List.of(),
                false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> ContainerSpecHardening.validate(spec));
        assertTrue(ex.getMessage().toLowerCase().contains("privileged"));
    }

    @Test
    void allowsPrivilegedForOperatorManagedSpec() {
        ContainerSpec spec = new ContainerSpec(
                "rancher/k3s:latest",
                null,
                List.of(),
                null,
                null,
                null,
                java.util.Map.of(),
                List.of(),
                null,
                List.of(),
                List.of(),
                List.of(),
                null,
                true,
                null,
                List.of(),
                null,
                null,
                List.of(),
                true);

        assertDoesNotThrow(() -> ContainerSpecHardening.validate(spec));
    }

    @Test
    void rejectsDockerSockBindForNonOperatorSpec() {
        ContainerSpec spec = new ContainerSpec(
                "busybox:latest",
                null,
                List.of(),
                null,
                null,
                null,
                java.util.Map.of(),
                List.of(),
                null,
                List.of(),
                List.of(new Bind("/var/run/docker.sock", new Volume("/var/run/docker.sock"))),
                List.of(),
                null,
                false,
                null,
                List.of(),
                null,
                null,
                List.of(),
                false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> ContainerSpecHardening.validate(spec));
        assertTrue(ex.getMessage().toLowerCase().contains("docker"));
    }

    @Test
    void rejectsDockerSockBindMountForNonOperatorSpec() {
        Mount sockMount = new Mount()
                .withType(MountType.BIND)
                .withSource("/var/run/docker.sock")
                .withTarget("/var/run/docker.sock");
        ContainerSpec spec = new ContainerSpec(
                "busybox:latest",
                null,
                List.of(),
                null,
                null,
                null,
                java.util.Map.of(),
                List.of(),
                null,
                List.of(sockMount),
                List.of(),
                List.of(),
                null,
                false,
                null,
                List.of(),
                null,
                null,
                List.of(),
                false);

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> ContainerSpecHardening.validate(spec));
        assertTrue(ex.getMessage().toLowerCase().contains("docker"));
    }

    @Test
    void rejectsWindowsDockerEngineNamedPipeBind() {
        ContainerSpec spec = new ContainerSpec(
                "busybox:latest",
                null,
                List.of(),
                null,
                null,
                null,
                java.util.Map.of(),
                List.of(),
                null,
                List.of(),
                List.of(new Bind("\\\\.\\pipe\\docker_engine", new Volume("/var/run/docker.sock"))),
                List.of(),
                null,
                false,
                null,
                List.of(),
                null,
                null,
                List.of(),
                false);

        assertThrows(IllegalArgumentException.class, () -> ContainerSpecHardening.validate(spec));
    }

    @Test
    void allowsOrdinaryBindForNonOperatorSpec() {
        ContainerSpec spec = new ContainerSpec(
                "busybox:latest",
                null,
                List.of(),
                null,
                null,
                null,
                java.util.Map.of(),
                List.of(),
                null,
                List.of(),
                List.of(new Bind("/tmp/data", new Volume("/data"))),
                List.of(),
                null,
                false,
                null,
                List.of(),
                null,
                null,
                List.of(),
                false);

        assertDoesNotThrow(() -> ContainerSpecHardening.validate(spec));
    }
}
