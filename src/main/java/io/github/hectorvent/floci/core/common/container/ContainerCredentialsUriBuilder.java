package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;

import java.util.function.IntSupplier;

/**
 * Builds container credential URIs and resolves HTTP bind addresses for
 * Lambda, CodeBuild, and ECS workload credential servers.
 */
public final class ContainerCredentialsUriBuilder {

    private final EmulatorConfig config;
    private final IntSupplier portSupplier;

    public ContainerCredentialsUriBuilder(EmulatorConfig config, IntSupplier portSupplier) {
        this.config = config;
        this.portSupplier = portSupplier;
    }

    public String credentialsRelativeUri(String credentialToken) {
        return "/v2/credentials/" + credentialToken;
    }

    public String credentialsFullUri(String hostAddress, String credentialToken) {
        if (config.ctf().containerCredentialsUseLinkLocalUri()) {
            return "http://" + config.ctf().containerCredentialsLinkLocalHost()
                    + credentialsRelativeUri(credentialToken);
        }
        int port = portSupplier.getAsInt();
        return "http://" + hostAddress + ":" + port + credentialsRelativeUri(credentialToken);
    }

    public String resolveBindHost() {
        if (config.ctf().containerCredentialsUseLinkLocalUri()) {
            return "0.0.0.0";
        }
        return config.ctf().containerCredentialsBindLocalhost() ? "127.0.0.1" : "0.0.0.0";
    }
}
