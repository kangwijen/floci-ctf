package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientSourceIpResolverTest {

    @Test
    void prefersStampedHeaderWhenEnabled() {
        EmulatorConfig config = mockConfig(true, false);
        assertEquals("203.0.113.1",
                ClientSourceIpResolver.resolve(config, "203.0.113.1", "10.0.0.1", "172.17.0.1"));
    }

    @Test
    void usesForwardedForWhenTrusted() {
        EmulatorConfig config = mockConfig(false, true);
        assertEquals("198.51.100.2",
                ClientSourceIpResolver.resolve(config, null, "198.51.100.2, 10.0.0.1", "172.17.0.1"));
    }

    @Test
    void fallsBackToSocketPeer() {
        EmulatorConfig config = mockConfig(false, false);
        assertEquals("172.17.0.1",
                ClientSourceIpResolver.resolve(config, null, null, "172.17.0.1"));
    }

    @Test
    void normalizesIpv6Loopback() {
        EmulatorConfig config = mockConfig(false, false);
        assertEquals("127.0.0.1",
                ClientSourceIpResolver.resolve(config, null, null, "::1"));
    }

    private static EmulatorConfig mockConfig(boolean allowStamped, boolean trustForwarded) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
        when(config.ctf()).thenReturn(ctf);
        when(config.auth()).thenReturn(auth);
        when(ctf.cloudTrailAllowSourceIpHeader()).thenReturn(allowStamped);
        when(auth.trustForwardedHeaders()).thenReturn(trustForwarded);
        return config;
    }
}
