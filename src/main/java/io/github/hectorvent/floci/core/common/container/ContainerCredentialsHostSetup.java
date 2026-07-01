package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.CurrentContainerNetworkResolver;

import java.util.Optional;

/**
 * Wires AWS-shaped link-local container credential URIs into Docker workload containers.
 *
 * <p>When link-local mode is on, {@code AWS_CONTAINER_CREDENTIALS_FULL_URI} uses
 * {@code http://169.254.170.2:PORT/v2/credentials/{token}}. Workloads must map that
 * address to a reachable Floci host:
 * <ul>
 *   <li>Floci on the Docker host: {@code extra_hosts: 169.254.170.2:host-gateway}</li>
 *   <li>Floci in Compose: {@code extra_hosts: 169.254.170.2:<floci-container-ip>}</li>
 * </ul>
 */
public final class ContainerCredentialsHostSetup {

    private ContainerCredentialsHostSetup() {
    }

    public record LinkLocalExtraHost(String hostname, String ip) {
        public String dockerExtraHostEntry() {
            return hostname + ":" + ip;
        }
    }

    /**
     * Returns an {@code /etc/hosts} entry when link-local credential URIs are enabled.
     */
    public static Optional<LinkLocalExtraHost> linkLocalExtraHost(
            EmulatorConfig config,
            ContainerDetector containerDetector,
            CurrentContainerNetworkResolver networkResolver,
            String fallbackFlociAddress) {
        if (!config.ctf().containerCredentialsUseLinkLocalUri()) {
            return Optional.empty();
        }
        String hostname = config.ctf().containerCredentialsLinkLocalHost();
        if (containerDetector.isRunningInContainer()) {
            String flociIp = networkResolver != null
                    ? networkResolver.resolveContainerIp().filter(ip -> !ip.isBlank()).orElse(null)
                    : null;
            if (flociIp == null || flociIp.isBlank()) {
                flociIp = fallbackFlociAddress;
            }
            return Optional.of(new LinkLocalExtraHost(hostname, flociIp));
        }
        return Optional.of(new LinkLocalExtraHost(hostname, "host-gateway"));
    }

    public static void applyLinkLocalExtraHost(ContainerBuilder.Builder specBuilder,
                                               EmulatorConfig config,
                                               ContainerDetector containerDetector,
                                               CurrentContainerNetworkResolver networkResolver,
                                               String fallbackFlociAddress) {
        linkLocalExtraHost(config, containerDetector, networkResolver, fallbackFlociAddress)
                .ifPresent(entry -> specBuilder.withExtraHost(entry.hostname(), entry.ip()));
    }
}
