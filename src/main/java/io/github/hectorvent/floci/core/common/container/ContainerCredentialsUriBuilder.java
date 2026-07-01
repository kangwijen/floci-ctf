package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;

import java.util.function.IntSupplier;

/**
 * Builds container credential URIs and resolves HTTP bind addresses for
 * Lambda, CodeBuild, and ECS workload credential servers.
 */
public final class ContainerCredentialsUriBuilder {

    private final EmulatorConfig config;
    private final IntSupplier portSupplier;
    private final ContainerDetector containerDetector;

    public ContainerCredentialsUriBuilder(EmulatorConfig config, IntSupplier portSupplier) {
        this(config, portSupplier, null);
    }

    public ContainerCredentialsUriBuilder(EmulatorConfig config, IntSupplier portSupplier,
                                          ContainerDetector containerDetector) {
        this.config = config;
        this.portSupplier = portSupplier;
        this.containerDetector = containerDetector;
    }

    public String credentialsRelativeUri(String credentialToken) {
        return "/v2/credentials/" + credentialToken;
    }

    /**
     * Whether to inject {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} into workloads.
     * Botocore prefers that variable and resolves it against {@code http://169.254.170.2}
     * on port 80. Floci credential servers use 9170/9171/9172 unless configured for port 80.
     */
    public boolean injectRelativeUri() {
        return portSupplier.getAsInt() == 80;
    }

    public String credentialsFullUri(String hostAddress, String credentialToken) {
        if (config.ctf().containerCredentialsUseLinkLocalUri()) {
            int port = portSupplier.getAsInt();
            return "http://" + config.ctf().containerCredentialsLinkLocalHost()
                    + ":" + port + credentialsRelativeUri(credentialToken);
        }
        int port = portSupplier.getAsInt();
        return "http://" + hostAddress + ":" + port + credentialsRelativeUri(credentialToken);
    }

    public String resolveBindHost() {
        if (config.ctf().containerCredentialsUseLinkLocalUri()) {
            return "0.0.0.0";
        }
        if (containerDetector != null && containerDetector.isRunningInContainer()) {
            return "0.0.0.0";
        }
        return config.ctf().containerCredentialsBindLocalhost() ? "127.0.0.1" : "0.0.0.0";
    }
}
