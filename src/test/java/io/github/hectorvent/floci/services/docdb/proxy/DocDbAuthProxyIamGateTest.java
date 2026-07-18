package io.github.hectorvent.floci.services.docdb.proxy;

import io.github.hectorvent.floci.services.rds.proxy.RdsSigV4Validator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * E-FO-03: IAM-enabled DocDB AuthProxy rejects ungated Mongo traffic and accepts
 * SigV4-shaped tokens presented as the Mongo PLAIN password.
 */
@Tag("security-regression")
class DocDbAuthProxyIamGateTest {

    private DocDbAuthProxy proxy;
    private ServerSocket backendServer;
    private final AtomicInteger backendAccepts = new AtomicInteger();

    @AfterEach
    void tearDown() {
        if (proxy != null) {
            proxy.stop();
        }
        if (backendServer != null) {
            try {
                backendServer.close();
            } catch (IOException ignored) {
            }
        }
    }

    @Test
    void iamEnabled_rejectsConnectionWithoutPlainAuth() throws Exception {
        int backendPort = startCountingBackend();
        RdsSigV4Validator sigV4 = mock(RdsSigV4Validator.class);
        when(sigV4.validate(anyString(), anyString())).thenReturn(false);

        int proxyPort = freePort();
        proxy = new DocDbAuthProxy(
                "cluster-a", true, "127.0.0.1", backendPort,
                "admin", "secret99", sigV4);
        proxy.start(proxyPort);
        awaitListening(proxyPort);

        try (Socket client = new Socket("127.0.0.1", proxyPort)) {
            client.setSoTimeout(2000);
            // Raw bytes with no Mongo PLAIN auth must not reach the backend.
            client.getOutputStream().write(new byte[]{1, 2, 3, 4});
            client.getOutputStream().flush();
            InputStream in = client.getInputStream();
            // Proxy should close or leave no backend accept.
            try {
                in.read();
            } catch (IOException ignored) {
            }
        }

        Thread.sleep(200);
        assertEquals(0, backendAccepts.get(), "ungated bytes must not bridge to Mongo backend");
    }

    @Test
    void iamEnabled_acceptsValidSigV4TokenViaPlainAuth() throws Exception {
        int backendPort = startCountingBackend();
        RdsSigV4Validator sigV4 = mock(RdsSigV4Validator.class);
        String token = "localhost:27018/?Action=connect&DBUser=admin&X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=AKIATEST%2F20260718%2Fus-east-1%2Frds-db%2Faws4_request"
                + "&X-Amz-Date=20260718T000000Z&X-Amz-Expires=900&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=deadbeef";
        when(sigV4.validate(eq(token), eq("admin"))).thenReturn(true);

        int proxyPort = freePort();
        proxy = new DocDbAuthProxy(
                "cluster-a", true, "127.0.0.1", backendPort,
                "admin", "secret99", sigV4);
        proxy.start(proxyPort);
        awaitListening(proxyPort);

        try (Socket client = new Socket("127.0.0.1", proxyPort)) {
            client.setSoTimeout(3000);
            OutputStream out = client.getOutputStream();
            InputStream in = client.getInputStream();

            out.write(DocDbMongoWireTestSupport.helloRequest());
            out.flush();
            byte[] helloResp = DocDbMongoWireTestSupport.readMessage(in);
            assertTrue(helloResp.length > 0);

            out.write(DocDbMongoWireTestSupport.plainSaslStart("admin", token));
            out.flush();
            byte[] authResp = DocDbMongoWireTestSupport.readMessage(in);
            assertTrue(DocDbMongoWireTestSupport.bodyContains(authResp, "ok"));
        }

        Thread.sleep(200);
        assertTrue(backendAccepts.get() >= 1,
                "valid SigV4 PLAIN auth must open a backend Mongo bridge");
    }

    @Test
    void iamDisabled_transparentBridgeWithoutAuth() throws Exception {
        AtomicBoolean backendSawTraffic = new AtomicBoolean(false);
        int backendPort = startEchoBackend(backendSawTraffic);
        RdsSigV4Validator sigV4 = mock(RdsSigV4Validator.class);

        int proxyPort = freePort();
        proxy = new DocDbAuthProxy(
                "cluster-b", false, "127.0.0.1", backendPort,
                "admin", "secret99", sigV4);
        proxy.start(proxyPort);
        awaitListening(proxyPort);

        try (Socket client = new Socket("127.0.0.1", proxyPort)) {
            client.setSoTimeout(2000);
            client.getOutputStream().write("raw-mongo".getBytes(StandardCharsets.UTF_8));
            client.getOutputStream().flush();
            byte[] echo = client.getInputStream().readNBytes(9);
            assertEquals("raw-mongo", new String(echo, StandardCharsets.UTF_8));
        }
        assertTrue(backendSawTraffic.get());
        assertFalse(sigV4.validate("x", "y")); // mock unused; keep analyzer quiet
    }

    private int startCountingBackend() throws IOException {
        backendServer = new ServerSocket(0);
        int port = backendServer.getLocalPort();
        Thread.ofVirtual().start(() -> {
            try {
                while (!backendServer.isClosed()) {
                    Socket s = backendServer.accept();
                    backendAccepts.incrementAndGet();
                    s.close();
                }
            } catch (IOException ignored) {
            }
        });
        return port;
    }

    private int startEchoBackend(AtomicBoolean sawTraffic) throws IOException {
        backendServer = new ServerSocket(0);
        int port = backendServer.getLocalPort();
        Thread.ofVirtual().start(() -> {
            try {
                while (!backendServer.isClosed()) {
                    Socket s = backendServer.accept();
                    Thread.ofVirtual().start(() -> {
                        try {
                            byte[] buf = new byte[256];
                            int n = s.getInputStream().read(buf);
                            if (n > 0) {
                                sawTraffic.set(true);
                                s.getOutputStream().write(buf, 0, n);
                                s.getOutputStream().flush();
                            }
                        } catch (IOException ignored) {
                        } finally {
                            try {
                                s.close();
                            } catch (IOException ignored) {
                            }
                        }
                    });
                }
            } catch (IOException ignored) {
            }
        });
        return port;
    }

    private static int freePort() throws IOException {
        try (ServerSocket ss = new ServerSocket(0)) {
            return ss.getLocalPort();
        }
    }

    private static void awaitListening(int port) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            try (Socket s = new Socket("127.0.0.1", port)) {
                return;
            } catch (IOException e) {
                Thread.sleep(20);
            }
        }
        throw new IllegalStateException("proxy not listening on " + port);
    }
}
