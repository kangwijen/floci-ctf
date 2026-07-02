package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

class ContainerCredentialsUriBuilderTest {

    @Test
    void injectRelativeUri_falseWhenPortIsNonStandard() {
        ContainerCredentialsUriBuilder builder = builder(9171, false, false);
        assertFalse(builder.injectRelativeUri());
    }

    @Test
    void injectRelativeUri_trueWhenPortIs80() {
        ContainerCredentialsUriBuilder builder = builder(80, false, false);
        assertTrue(builder.injectRelativeUri());
    }

    @Test
    void credentialsFullUri_usesLinkLocalHostOnNativeDockerHost() {
        ContainerCredentialsUriBuilder builder = builder(9171, true, false);
        assertEquals("http://169.254.170.2:9171/v2/credentials/token-1",
                builder.credentialsFullUri("127.0.0.1", "token-1"));
    }

    @Test
    void credentialsFullUri_usesLocalhostWhenFlociRunsInsideDocker() {
        ContainerCredentialsUriBuilder builder = builder(9171, true, true);
        assertEquals("http://127.0.0.1:9171/v2/credentials/token-1",
                builder.credentialsFullUri("172.18.0.2", "token-1"));
    }

    @Test
    void credentialsFullUri_usesHostAddressWhenLinkLocalDisabled() {
        ContainerCredentialsUriBuilder builder = builder(9171, false, false);
        assertEquals("http://172.20.0.5:9171/v2/credentials/token-1",
                builder.credentialsFullUri("172.20.0.5", "token-1"));
    }

    private static ContainerCredentialsUriBuilder builder(int port, boolean linkLocal, boolean inContainer) {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class);
        EmulatorConfig.CtfConfig ctf = Mockito.mock(EmulatorConfig.CtfConfig.class);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(linkLocal);
        when(ctf.containerCredentialsLinkLocalHost()).thenReturn("169.254.170.2");
        when(ctf.containerCredentialsBindLocalhost()).thenReturn(false);

        ContainerDetector detector = Mockito.mock(ContainerDetector.class);
        when(detector.isRunningInContainer()).thenReturn(inContainer);

        return new ContainerCredentialsUriBuilder(config, () -> port, detector);
    }
}
