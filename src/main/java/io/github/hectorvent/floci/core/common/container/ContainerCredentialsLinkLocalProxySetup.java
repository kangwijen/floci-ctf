package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerExecResult;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import org.jboss.logging.Logger;

/**
 * Starts the in-container localhost proxy for {@code AWS_CONTAINER_CREDENTIALS_FULL_URI}.
 */
public final class ContainerCredentialsLinkLocalProxySetup {

    private static final Logger LOG = Logger.getLogger(ContainerCredentialsLinkLocalProxySetup.class);

    private ContainerCredentialsLinkLocalProxySetup() {
    }

    public static void applyIfRequired(ContainerLifecycleManager lifecycleManager,
                                       EmulatorConfig config,
                                       ContainerDetector containerDetector,
                                       String containerId,
                                       String upstreamHost,
                                       int upstreamPort) {
        if (!ContainerCredentialsLinkLocalProxy.required(config, containerDetector)) {
            return;
        }
        try {
            ContainerExecResult start = lifecycleManager.execForResult(
                    containerId,
                    ContainerCredentialsLinkLocalProxy.startLocalhostProxyCommand(
                            upstreamPort, upstreamHost, upstreamPort),
                    30);
            if (start.exitCode() != 0) {
                LOG.warnv("Could not start localhost container credentials proxy for {0}: {1}",
                        containerId, start.summary());
                return;
            }

            LOG.debugv("Configured localhost container credentials proxy for {0} -> {1}:{2}",
                    containerId, upstreamHost, upstreamPort);
        } catch (Exception e) {
            LOG.warnv("Could not configure localhost container credentials proxy for {0}: {1}",
                    containerId, e.getMessage());
        }
    }
}
