package io.github.hectorvent.floci.core.common.port;

import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Hands out ports from a configured range for Lambda Runtime API servers.
 * Skips ports that are already bound on the host (for example Elasticsearch on
 * 9200, or leaked Runtime API servers from a prior test lifecycle). When the
 * configured range is exhausted or entirely busy, falls back to an ephemeral
 * port from the OS. The caller releases a port back to the pool via
 * {@link #release(int)}.
 */
@ApplicationScoped
public class PortAllocator {

    private final int basePort;
    private final int maxPort;
    private final boolean allowEphemeral;
    private final Set<Integer> inUse = ConcurrentHashMap.newKeySet();

    @Inject
    public PortAllocator(EmulatorConfig config) {
        this(config.services().lambda().runtimeApiBasePort(),
                config.services().lambda().runtimeApiMaxPort(),
                true);
    }

    PortAllocator(int basePort, int maxPort) {
        this(basePort, maxPort, true);
    }

    PortAllocator(int basePort, int maxPort, boolean allowEphemeral) {
        this.basePort = basePort;
        this.maxPort = maxPort;
        this.allowEphemeral = allowEphemeral;
    }

    public int allocate() {
        for (int p = basePort; p <= maxPort; p++) {
            if (!inUse.contains(p) && isPortFree(p) && inUse.add(p)) {
                return p;
            }
        }
        if (allowEphemeral) {
            return allocateEphemeral();
        }
        throw new IllegalStateException(
                "No free ports in range " + basePort + "-" + maxPort);
    }

    public void release(int port) {
        inUse.remove(port);
    }

    private int allocateEphemeral() {
        for (int attempt = 0; attempt < 50; attempt++) {
            int port = reserveEphemeralPort();
            if (port > 0 && !inUse.contains(port) && inUse.add(port)) {
                return port;
            }
        }
        throw new IllegalStateException(
                "No free ports in range " + basePort + "-" + maxPort + " or via ephemeral allocation");
    }

    private static int reserveEphemeralPort() {
        // Localhost ephemeral port bind probe only, not a network listener.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        } catch (IOException e) {
            return -1;
        }
    }

    public static boolean isPortFree(int port) {
        // Localhost port bind probe only, not a network listener.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        try (ServerSocket socket = new ServerSocket(port)) {
            socket.setReuseAddress(true);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Allocates a port from {@code [base, max]} that is not already tracked in
     * {@code inUse} and is free to bind on the host. When {@code allowEphemeral}
     * is true and the configured range is exhausted, falls back to an OS-assigned
     * ephemeral port (same strategy as Lambda Runtime API allocation).
     *
     * @return allocated port, or {@code -1} when none is available
     */
    public static int allocateFromRange(int base, int max, Set<Integer> inUse, boolean allowEphemeral) {
        for (int port = base; port <= max; port++) {
            if (!inUse.contains(port) && isPortFree(port) && inUse.add(port)) {
                return port;
            }
        }
        if (!allowEphemeral) {
            return -1;
        }
        for (int attempt = 0; attempt < 50; attempt++) {
            int port = reserveEphemeralPort();
            if (port > 0 && !inUse.contains(port) && inUse.add(port)) {
                return port;
            }
        }
        return -1;
    }
}
