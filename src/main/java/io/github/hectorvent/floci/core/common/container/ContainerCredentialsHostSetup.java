package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.CurrentContainerNetworkResolver;

import java.util.Optional;

/**
 * Wires AWS-shaped link-local container credential URIs into Docker workload containers.
 *
 * <p>When link-local mode is on and Floci runs on the Docker host, {@code extra_hosts}
 * maps {@code 169.254.170.2} to {@code host-gateway}. When Floci runs inside Docker,
 * {@link ContainerCredentialsLinkLocalProxy} runs a localhost TCP proxy in each workload
 * container and {@code FULL_URI} uses {@code 127.0.0.1} (a boto3-allowed metadata host).
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
            // FULL_URI uses FLOCI_HOSTNAME or container IP; extra_hosts cannot remap link-local.
            return Optional.empty();
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
