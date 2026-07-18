package io.github.hectorvent.floci.services.elasticache.proxy;

import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * TCP auth proxy for ElastiCache Memcached clusters (Redis AuthProxy pattern).
 *
 * <p>Host clients connect to the proxy port. The Docker Memcached port stays on the container
 * network. When {@code authRequired} is true (CTF IAM enforcement), the first ASCII line must be
 * {@code auth &lt;token&gt;} with a SigV4 IAM token validated like Redis AUTH. When auth is not
 * required, the proxy is a transparent byte bridge.
 */
public class ElastiCacheMemcachedAuthProxy {

    private static final Logger LOG = Logger.getLogger(ElastiCacheMemcachedAuthProxy.class);

    private static final byte[] AUTH_ERROR =
            "ERROR authentication required\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AUTH_OK = "OK\r\n".getBytes(StandardCharsets.US_ASCII);

    private final String clusterId;
    private final boolean authRequired;
    private final String backendHost;
    private final int backendPort;
    private final SigV4Validator sigV4Validator;

    private volatile boolean running;
    private ServerSocket serverSocket;

    public ElastiCacheMemcachedAuthProxy(String clusterId, boolean authRequired,
                                         String backendHost, int backendPort,
                                         SigV4Validator sigV4Validator) {
        this.clusterId = clusterId;
        this.authRequired = authRequired;
        this.backendHost = backendHost;
        this.backendPort = backendPort;
        this.sigV4Validator = sigV4Validator;
    }

    public void start(int proxyPort) throws IOException {
        // Intentional localhost Memcached proxy listener; mirrors AWS ElastiCache wire protocol, not TLS-terminated.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        serverSocket = new ServerSocket(proxyPort);
        serverSocket.setReuseAddress(true);
        running = true;
        Thread.ofVirtual().name("ec-mc-proxy-accept-" + clusterId).start(this::acceptLoop);
        LOG.infov("ElastiCache Memcached proxy started for cluster {0} on port {1} → {2}:{3} auth={4}",
                clusterId, String.valueOf(proxyPort), backendHost, String.valueOf(backendPort), authRequired);
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOG.warnv("Error closing Memcached proxy for cluster {0}: {1}", clusterId, e.getMessage());
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                Thread.ofVirtual().name("ec-mc-proxy-conn-" + clusterId).start(() -> handleConnection(client));
            } catch (IOException e) {
                if (running) {
                    LOG.warnv("Accept error for Memcached cluster {0}: {1}", clusterId, e.getMessage());
                }
            }
        }
    }

    private void handleConnection(Socket client) {
        try {
            client.setTcpNoDelay(true);
            if (!authRequired) {
                // Intentional localhost backend relay; Memcached to co-located container, not TLS-terminated.
                // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
                Socket backend = new Socket(backendHost, backendPort);
                backend.setTcpNoDelay(true);
                bridge(client, backend);
                return;
            }

            String firstLine = readAsciiLine(client.getInputStream());
            if (firstLine == null || !firstLine.regionMatches(true, 0, "auth ", 0, 5)) {
                client.getOutputStream().write(AUTH_ERROR);
                client.getOutputStream().flush();
                closeQuietly(client);
                return;
            }
            String token = firstLine.substring(5).trim();
            boolean ok = sigV4Validator != null && sigV4Validator.validate(token, clusterId, null);
            if (!ok) {
                client.getOutputStream().write(AUTH_ERROR);
                client.getOutputStream().flush();
                closeQuietly(client);
                return;
            }
            client.getOutputStream().write(AUTH_OK);
            client.getOutputStream().flush();

            // Intentional localhost backend relay; Memcached to co-located container, not TLS-terminated.
            // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
            Socket backend = new Socket(backendHost, backendPort);
            backend.setTcpNoDelay(true);
            bridge(client, backend);
        } catch (Exception e) {
            LOG.debugv("Memcached proxy connection error for cluster {0}: {1}", clusterId, e.getMessage());
            closeQuietly(client);
        }
    }

    private void bridge(Socket client, Socket backend) {
        Thread t1 = Thread.ofPlatform().daemon(true).name("ec-mc-relay-c2b-" + clusterId)
                .start(() -> pipe(client, backend));
        Thread t2 = Thread.ofPlatform().daemon(true).name("ec-mc-relay-b2c-" + clusterId)
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
        }
    }

    static String readAsciiLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) {
            int b = in.read();
            if (b == -1) {
                return sb.isEmpty() ? null : sb.toString();
            }
            if (b == '\n') {
                break;
            }
            if (b != '\r') {
                sb.append((char) b);
            }
            if (sb.length() > 65536) {
                throw new IOException("AUTH line too long");
            }
        }
        return sb.toString();
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }
}
