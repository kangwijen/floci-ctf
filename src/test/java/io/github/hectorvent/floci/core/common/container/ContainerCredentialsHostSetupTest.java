package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.CurrentContainerNetworkResolver;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ContainerCredentialsHostSetupTest {

    @Test
    void linkLocalExtraHostUsesHostGatewayWhenFlociOnNativeHost() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        ContainerDetector detector = mock(ContainerDetector.class);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(true);
        when(ctf.containerCredentialsLinkLocalHost()).thenReturn("169.254.170.2");
        when(detector.isRunningInContainer()).thenReturn(false);

        Optional<ContainerCredentialsHostSetup.LinkLocalExtraHost> entry =
                ContainerCredentialsHostSetup.linkLocalExtraHost(config, detector, null, "172.18.0.2");

        assertTrue(entry.isPresent());
        assertEquals("169.254.170.2:host-gateway", entry.get().dockerExtraHostEntry());
    }

    @Test
    void linkLocalExtraHostAbsentWhenFlociRunsInsideDocker() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        ContainerDetector detector = mock(ContainerDetector.class);
        CurrentContainerNetworkResolver networkResolver = mock(CurrentContainerNetworkResolver.class);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(true);
        when(ctf.containerCredentialsLinkLocalHost()).thenReturn("169.254.170.2");
        when(detector.isRunningInContainer()).thenReturn(true);
        when(networkResolver.resolveContainerIp()).thenReturn(Optional.of("172.20.0.5"));

        assertTrue(ContainerCredentialsHostSetup.linkLocalExtraHost(
                config, detector, networkResolver, "172.18.0.2").isEmpty());
    }

    @Test
    void linkLocalExtraHostAbsentWhenLinkLocalDisabled() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(false);

        assertTrue(ContainerCredentialsHostSetup.linkLocalExtraHost(
                config, mock(ContainerDetector.class), null, "127.0.0.1").isEmpty());
    }
}
