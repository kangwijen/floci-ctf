package io.github.hectorvent.floci.core.common.container;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ContainerCredentialsLinkLocalProxyTest {

    @Test
    void startLocalhostProxyCommandUsesPythonRelayOnLoopback() {
        String[] command = ContainerCredentialsLinkLocalProxy.startLocalhostProxyCommand(
                9171, "floci", 9171);
        String script = String.join(" ", command);
        assertTrue(script.contains("LISTEN = ('127.0.0.1', 9171)"));
        assertTrue(script.contains("REMOTE = ('floci', 9171)"));
        assertTrue(script.contains("nohup python3"));
    }
}
