package io.github.hectorvent.floci.services.docdb.proxy;

import io.github.hectorvent.floci.services.rds.proxy.RdsSigV4Validator;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * TCP AuthProxy for a DocumentDB cluster endpoint.
 *
 * <p>When IAM database authentication is disabled the proxy is a transparent
 * byte relay (password SCRAM is enforced by the MongoDB container). When IAM
 * is enabled the proxy terminates Mongo hello/PLAIN auth, validates a SigV4
 * generate-db-auth-token (or the master password), authenticates to the
 * backend as the master user, then bridges.
 */
public class DocDbAuthProxy {

    private static final Logger LOG = Logger.getLogger(DocDbAuthProxy.class);

    private final String clusterId;
    private final boolean iamEnabled;
    private final String backendHost;
    private final int backendPort;
    private final String masterUsername;
    private final String masterPassword;
    private final RdsSigV4Validator sigV4;
    private final BackendAuthenticator backendAuthenticator;

    private volatile boolean running;
    private ServerSocket serverSocket;

    public DocDbAuthProxy(String clusterId, boolean iamEnabled,
                          String backendHost, int backendPort,
                          String masterUsername, String masterPassword,
                          RdsSigV4Validator sigV4) {
        this(clusterId, iamEnabled, backendHost, backendPort,
                masterUsername, masterPassword, sigV4, BackendAuthenticator.NOOP);
    }

    public DocDbAuthProxy(String clusterId, boolean iamEnabled,
                          String backendHost, int backendPort,
                          String masterUsername, String masterPassword,
                          RdsSigV4Validator sigV4,
                          BackendAuthenticator backendAuthenticator) {
        this.clusterId = clusterId;
        this.iamEnabled = iamEnabled;
        this.backendHost = backendHost;
        this.backendPort = backendPort;
        this.masterUsername = masterUsername;
        this.masterPassword = masterPassword;
        this.sigV4 = sigV4;
        this.backendAuthenticator = backendAuthenticator != null
                ? backendAuthenticator : BackendAuthenticator.NOOP;
    }

    public void start(int proxyPort) throws IOException {
        // Intentional localhost Mongo wire proxy; mirrors DocumentDB wire access, not TLS-terminated.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        serverSocket = new ServerSocket(proxyPort);
        serverSocket.setReuseAddress(true);
        running = true;
        Thread.ofVirtual().name("docdb-proxy-accept-" + clusterId).start(this::acceptLoop);
        LOG.infov("DocumentDB AuthProxy started for cluster {0} on port {1} → {2}:{3} (iam={4})",
                clusterId, String.valueOf(proxyPort), backendHost, String.valueOf(backendPort),
                String.valueOf(iamEnabled));
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            LOG.warnv("Error closing DocDB proxy for cluster {0}: {1}", clusterId, e.getMessage());
        }
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket client = serverSocket.accept();
                Thread.ofVirtual().name("docdb-proxy-conn-" + clusterId)
                        .start(() -> handleConnection(client));
            } catch (IOException e) {
                if (running) {
                    LOG.warnv("Accept error for DocDB cluster {0}: {1}", clusterId, e.getMessage());
                }
            }
        }
    }

    private void handleConnection(Socket client) {
        try {
            client.setTcpNoDelay(true);
            if (!iamEnabled) {
                transparentBridge(client);
                return;
            }
            handleIamAuth(client);
        } catch (Exception e) {
            LOG.debugv("DocDB proxy connection error for cluster {0}: {1}", clusterId, e.getMessage());
            closeQuietly(client);
        }
    }

    private void transparentBridge(Socket client) throws IOException {
        // Intentional localhost backend relay to co-located Mongo container.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        Socket backend = new Socket(backendHost, backendPort);
        backend.setTcpNoDelay(true);
        bridge(client, backend);
    }

    private void handleIamAuth(Socket client) throws IOException {
        InputStream clientIn = client.getInputStream();
        OutputStream clientOut = client.getOutputStream();

        byte[] first = DocDbMongoWire.readMessage(clientIn);
        if (first.length < 16) {
            closeQuietly(client);
            return;
        }

        if (DocDbMongoWire.isHello(first)) {
            clientOut.write(DocDbMongoWire.helloOkResponse(DocDbMongoWire.requestId(first)));
            clientOut.flush();
            first = DocDbMongoWire.readMessage(clientIn);
            if (first.length < 16) {
                closeQuietly(client);
                return;
            }
        }

        DocDbMongoWire.PlainCredentials creds = DocDbMongoWire.parsePlainSaslStart(first);
        if (creds == null) {
            clientOut.write(DocDbMongoWire.authFailureResponse(
                    DocDbMongoWire.requestId(first), "Authentication required (PLAIN + SigV4 token)"));
            clientOut.flush();
            closeQuietly(client);
            return;
        }

        boolean valid;
        if (creds.password().contains("X-Amz-Signature")) {
            valid = sigV4.validate(creds.password(), creds.username());
        } else if (masterUsername.equals(creds.username())) {
            valid = masterPassword.equals(creds.password());
        } else {
            valid = false;
        }

        if (!valid) {
            clientOut.write(DocDbMongoWire.authFailureResponse(
                    DocDbMongoWire.requestId(first), "Authentication failed"));
            clientOut.flush();
            closeQuietly(client);
            return;
        }

        // Intentional localhost backend relay to co-located Mongo container.
        // nosemgrep: java.lang.security.audit.crypto.unencrypted-socket.unencrypted-socket
        Socket backend = new Socket(backendHost, backendPort);
        backend.setTcpNoDelay(true);
        try {
            backendAuthenticator.authenticate(backend, masterUsername, masterPassword);
        } catch (IOException e) {
            clientOut.write(DocDbMongoWire.authFailureResponse(
                    DocDbMongoWire.requestId(first), "Backend authentication failed"));
            clientOut.flush();
            closeQuietly(client);
            closeQuietly(backend);
            return;
        }

        clientOut.write(DocDbMongoWire.saslSuccessResponse(DocDbMongoWire.requestId(first)));
        clientOut.flush();
        bridge(client, backend);
    }

    private void bridge(Socket client, Socket backend) {
        Thread t1 = Thread.ofPlatform().daemon(true).name("docdb-relay-c2b-" + clusterId)
                .start(() -> pipe(client, backend));
        Thread t2 = Thread.ofPlatform().daemon(true).name("docdb-relay-b2c-" + clusterId)
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

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    @FunctionalInterface
    public interface BackendAuthenticator {
        BackendAuthenticator NOOP = (backend, user, password) -> { };

        void authenticate(Socket backend, String username, String password) throws IOException;
    }
}
