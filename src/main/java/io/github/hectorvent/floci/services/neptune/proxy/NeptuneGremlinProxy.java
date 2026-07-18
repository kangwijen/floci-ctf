package io.github.hectorvent.floci.services.neptune.proxy;

import org.jboss.logging.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Transparent TCP proxy for a single Neptune DB cluster's Gremlin endpoint.
 *
 * <p>Neptune uses WebSocket over port 8182. The client (botocore / gremlin drivers) embeds SigV4
 * credentials in the HTTP Upgrade headers. The backend TinkerPop Gremlin Server accepts plain
 * WebSocket without authentication. When {@link HandshakeAuthenticator} is set (CTF IAM
 * enforcement), the proxy reads the upgrade request, validates SigV4 or an auth token, then relays.
 * When no authenticator is set (lab), bytes are relayed without inspection.
 *
 * <p>Uses Java virtual threads for non-blocking I/O.
 */
public class NeptuneGremlinProxy {

    private static final Logger LOG = Logger.getLogger(NeptuneGremlinProxy.class);

    private static final String FORBIDDEN_RESPONSE =
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    private final String clusterId;
    private final String backendHost;
    private final int backendPort;
    private final HandshakeAuthenticator authenticator;

    private volatile boolean running;
    private ServerSocket serverSocket;

    public NeptuneGremlinProxy(String clusterId, String backendHost, int backendPort) {
        this(clusterId, backendHost, backendPort, null);
    }

    public NeptuneGremlinProxy(String clusterId, String backendHost, int backendPort,
                               HandshakeAuthenticator authenticator) {
        this.clusterId = clusterId;
        this.backendHost = backendHost;
        this.backendPort = backendPort;
        this.authenticator = authenticator;
    }

    public void start(int proxyPort) throws IOException {
        // Intentional localhost Gremlin proxy listener; mirrors AWS Neptune wire protocol, not TLS-terminated.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        serverSocket = new ServerSocket(proxyPort);
        running = true;
        Thread.ofVirtual().name("neptune-proxy-accept-" + clusterId).start(this::acceptLoop);
        LOG.infov("Neptune Gremlin proxy started for cluster {0} on port {1} → {2}:{3} auth={4}",
                clusterId, String.valueOf(proxyPort), backendHost, String.valueOf(backendPort),
                authenticator != null);
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOG.warnv("Error closing proxy server socket for cluster {0}: {1}", clusterId, e.getMessage());
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                Thread.ofVirtual().name("neptune-proxy-conn-" + clusterId).start(() -> relay(client));
            } catch (IOException e) {
                if (running) {
                    LOG.warnv("Accept error for cluster {0}: {1}", clusterId, e.getMessage());
                }
            }
        }
    }

    private void relay(Socket client) {
        try {
            client.setTcpNoDelay(true);
            if (authenticator == null) {
                // Intentional localhost backend relay; Gremlin WebSocket to co-located TinkerPop, not TLS-terminated.
                // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
                Socket backend = new Socket(backendHost, backendPort);
                backend.setTcpNoDelay(true);
                bridge(client, backend);
                return;
            }

            HandshakeBuffer handshake = readHttpHeaders(client.getInputStream());
            if (!authenticator.accept(handshake.headersText(), clusterId)) {
                LOG.debugv("Neptune Gremlin handshake rejected for cluster {0}", clusterId);
                client.getOutputStream().write(FORBIDDEN_RESPONSE.getBytes(StandardCharsets.US_ASCII));
                client.getOutputStream().flush();
                closeQuietly(client);
                return;
            }

            // Intentional localhost backend relay; Gremlin WebSocket to co-located TinkerPop, not TLS-terminated.
            // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
            Socket backend = new Socket(backendHost, backendPort);
            backend.setTcpNoDelay(true);
            backend.getOutputStream().write(handshake.rawBytes());
            backend.getOutputStream().flush();
            bridge(client, backend);
        } catch (IOException e) {
            LOG.debugv("Failed to connect to Gremlin backend for cluster {0}: {1}",
                    clusterId, e.getMessage());
            closeQuietly(client);
        }
    }

    /**
     * Bidirectional byte relay. Relay threads are platform daemon threads; virtual threads
     * for I/O-bound work can stall WebSocket frame delivery under high concurrency.
     */
    private void bridge(Socket client, Socket backend) {
        Thread t1 = Thread.ofPlatform().daemon(true).name("neptune-relay-c2b-" + clusterId)
                .start(() -> pipe(client, backend));
        Thread t2 = Thread.ofPlatform().daemon(true).name("neptune-relay-b2c-" + clusterId)
                .start(() -> pipe(backend, client));
        try {
            t1.join();
            t2.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            closeQuietly(client);
            closeQuietly(backend);
        }
    }

    private static void pipe(Socket from, Socket to) {
        byte[] buf = new byte[8192];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignored) {
            // Normal when either side closes the connection
        }
    }

    static HandshakeBuffer readHttpHeaders(InputStream in) throws IOException {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        int state = 0;
        while (state < 4) {
            int b = in.read();
            if (b == -1) {
                break;
            }
            raw.write(b);
            if (b == '\r' && (state == 0 || state == 2)) {
                state++;
            } else if (b == '\n' && (state == 1 || state == 3)) {
                state++;
            } else {
                state = 0;
            }
            if (raw.size() > 65536) {
                throw new IOException("HTTP handshake too large");
            }
        }
        return new HandshakeBuffer(raw.toByteArray());
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    @FunctionalInterface
    public interface HandshakeAuthenticator {
        boolean accept(String headersText, String clusterId);
    }

    record HandshakeBuffer(byte[] rawBytes) {
        String headersText() {
            return new String(rawBytes, StandardCharsets.US_ASCII);
        }

        boolean hasAuthorization() {
            String lower = headersText().toLowerCase(Locale.ROOT);
            return lower.contains("\nauthorization:") || lower.startsWith("authorization:");
        }
    }
}
