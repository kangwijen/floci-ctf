package io.github.hectorvent.floci.services.opensearch.proxy;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.opensearch.model.AdvancedSecurityOptions;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * E-FO-04: domain HTTP side effects require IAM (or FGAC) before proxying.
 */
@Tag("security-regression")
class OpenSearchDataPlaneGateTest {

    private Vertx vertx;
    private OpenSearchDataPlane dataPlane;
    private AtomicInteger backendHits;
    private int backendPort;
    private io.vertx.core.http.HttpServer backendServer;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
        backendHits = new AtomicInteger();
        backendServer = vertx.createHttpServer();
        backendServer.requestHandler(req -> {
            backendHits.incrementAndGet();
            req.response().setStatusCode(200).end("{\"backend\":true}");
        });
        backendServer.listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().join();
        backendPort = backendServer.actualPort();
    }

    @AfterEach
    void tearDown() {
        if (dataPlane != null) {
            dataPlane.stopAll();
        }
        if (backendServer != null) {
            backendServer.close().toCompletionStage().toCompletableFuture().join();
        }
        if (vertx != null) {
            vertx.close().toCompletionStage().toCompletableFuture().join();
        }
    }

    @Test
    void enforcementOn_unsignedMutatingRequestIsDeniedBeforeBackend() throws Exception {
        EmulatorConfig config = mockConfig(true);
        dataPlane = new OpenSearchDataPlane(
                vertx, config, mock(IamService.class),
                mock(IamPolicyEvaluator.class), mock(ResourcePolicyResolver.class));

        int proxyPort = freePort();
        dataPlane.start("dom", proxyPort, "http://127.0.0.1:" + backendPort,
                "arn:aws:es:us-east-1:000000000000:domain/dom", null);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + proxyPort + "/books/_doc/1"))
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString("{\"a\":1}", StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertEquals(401, resp.statusCode());
        assertEquals(0, backendHits.get(), "unsigned side effect must not reach domain HTTP");
    }

    @Test
    void fgacEnabled_rejectsAnonymousEvenWhenIamEnforcementOff() throws Exception {
        EmulatorConfig config = mockConfig(false);
        dataPlane = new OpenSearchDataPlane(
                vertx, config, mock(IamService.class),
                mock(IamPolicyEvaluator.class), mock(ResourcePolicyResolver.class));

        AdvancedSecurityOptions fgac = new AdvancedSecurityOptions();
        fgac.setEnabled(true);
        AdvancedSecurityOptions.MasterUserOptions master = new AdvancedSecurityOptions.MasterUserOptions();
        master.setMasterUserName("admin");
        fgac.setMasterUserOptions(master);

        int proxyPort = freePort();
        dataPlane.start("dom", proxyPort, "http://127.0.0.1:" + backendPort,
                "arn:aws:es:us-east-1:000000000000:domain/dom", fgac);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:" + proxyPort + "/_search"))
                .GET()
                .build();
        HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());

        assertTrue(resp.statusCode() == 401 || resp.statusCode() == 403);
        assertEquals(0, backendHits.get());
    }

    private static EmulatorConfig mockConfig(boolean enforcement) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iam = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iam);
        when(iam.enforcementEnabled()).thenReturn(enforcement);
        when(config.auth()).thenReturn(auth);
        when(auth.rootAccessKeyId()).thenReturn(Optional.empty());
        return config;
    }

    private static int freePort() throws Exception {
        try (java.net.ServerSocket ss = new java.net.ServerSocket(0)) {
            return ss.getLocalPort();
        }
    }
}
