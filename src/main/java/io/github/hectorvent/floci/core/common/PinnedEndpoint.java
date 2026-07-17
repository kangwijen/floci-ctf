package io.github.hectorvent.floci.core.common;

import java.net.InetAddress;
import java.net.URI;

/**
 * Result of resolve-then-validate pin-connect: TCP/TLS must use {@link #pinnedAddress()}
 * (via {@link #connectUri()}) while Host/SNI use {@link #hostname()}.
 */
public record PinnedEndpoint(
        URI originalUri,
        URI connectUri,
        String hostname,
        InetAddress pinnedAddress,
        int port,
        boolean https) {

    public String hostHeader() {
        int defaultPort = https ? 443 : 80;
        if (port <= 0 || port == defaultPort) {
            return hostname;
        }
        return hostname + ":" + port;
    }
}
