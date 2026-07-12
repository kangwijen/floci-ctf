package io.github.hectorvent.floci.services.athena;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.OperatorCredentialEnv;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.core.common.docker.DockerHostResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.athena.model.QueryExecution;
import io.github.hectorvent.floci.services.athena.model.QueryExecutionState;
import io.github.hectorvent.floci.services.floci.duck.FlociDuckClient;
import io.github.hectorvent.floci.services.floci.duck.FlociDuckManager;
import io.github.hectorvent.floci.services.glue.GlueService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression for VULN-4: under IAM enforcement, FlociDuckClient must not inject
 * OperatorCredentialEnv into Duck S3 keys, and Athena mock=false must fail closed
 * rather than escalate to operator root for s3:// reads.
 */
@ExtendWith(MockitoExtension.class)
class AthenaDuckOperatorS3BypassIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock FlociDuckManager duckManager;
    @Mock EmulatorConfig config;
    @Mock EmulatorConfig.ServicesConfig servicesConfig;
    @Mock EmulatorConfig.AthenaServiceConfig athenaConfig;
    @Mock EmulatorConfig.IamServiceConfig iamConfig;
    @Mock EmbeddedDnsServer embeddedDnsServer;
    @Mock DockerHostResolver dockerHostResolver;
    @Mock StorageFactory storageFactory;
    @Mock GlueService glueService;
    @Mock S3Service s3Service;
    @Mock FlociDuckClient duckClientMock;

    private Vertx vertx;
    private HttpServer captureServer;
    private final AtomicReference<String> capturedExecuteBody = new AtomicReference<>();

    @BeforeEach
    void setUp() throws IOException {
        vertx = Vertx.vertx();
        lenient().when(storageFactory.create(anyString(), anyString(), any()))
                .thenAnswer(inv -> new InMemoryStorage<>());
        lenient().when(config.services()).thenReturn(servicesConfig);
        lenient().when(servicesConfig.iam()).thenReturn(iamConfig);
        lenient().when(servicesConfig.athena()).thenReturn(athenaConfig);
    }

    @AfterEach
    void tearDown() {
        if (captureServer != null) {
            captureServer.stop(0);
        }
        if (vertx != null) {
            vertx.close();
        }
    }

    @Test
    void buildBaseBodyUnderEnforcementOmitsOperatorCredentialEnvKeys() throws Exception {
        Map<String, String> operatorCreds = OperatorCredentialEnv.snapshot();
        Assumptions.assumeFalse(operatorCreds.isEmpty(),
                "Host must expose AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for this assertion");
        Assumptions.assumeTrue(operatorCreds.containsKey("AWS_ACCESS_KEY_ID"));
        Assumptions.assumeTrue(operatorCreds.containsKey("AWS_SECRET_ACCESS_KEY"));

        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(config.defaultRegion()).thenReturn("us-east-1");
        when(config.baseUrl()).thenReturn("http://127.0.0.1:4566");
        when(embeddedDnsServer.getServerIp()).thenReturn(Optional.empty());
        when(dockerHostResolver.resolve()).thenReturn("127.0.0.1");

        FlociDuckClient client = new FlociDuckClient(
                duckManager, config, embeddedDnsServer, dockerHostResolver, MAPPER);

        Method buildBaseBody = FlociDuckClient.class.getDeclaredMethod(
                "buildBaseBody", String.class, String.class, String.class);
        buildBaseBody.setAccessible(true);

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) buildBaseBody.invoke(
                client, "SELECT 1", null, null);

        assertFalse(body.containsKey("s3_access_key"),
                "IAM enforcement must not inject OperatorCredentialEnv AWS_ACCESS_KEY_ID");
        assertFalse(body.containsKey("s3_secret_key"),
                "IAM enforcement must not inject OperatorCredentialEnv AWS_SECRET_ACCESS_KEY");
        assertNotEquals(operatorCreds.get("AWS_ACCESS_KEY_ID"), body.get("s3_access_key"));
        assertNotEquals(operatorCreds.get("AWS_SECRET_ACCESS_KEY"), body.get("s3_secret_key"));
    }

    @Test
    void executeHttpBodyOmitsOperatorKeysUnderEnforcement() throws Exception {
        Map<String, String> operatorCreds = OperatorCredentialEnv.snapshot();
        Assumptions.assumeFalse(operatorCreds.isEmpty(),
                "Host must expose AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY for this assertion");

        when(iamConfig.enforcementEnabled()).thenReturn(true);
        startCaptureServer();
        when(duckManager.ensureReady()).thenReturn(baseUrl());
        when(config.defaultRegion()).thenReturn("us-east-1");
        when(config.baseUrl()).thenReturn("http://127.0.0.1:4566");
        when(embeddedDnsServer.getServerIp()).thenReturn(Optional.empty());
        when(dockerHostResolver.resolve()).thenReturn("127.0.0.1");

        FlociDuckClient client = new FlociDuckClient(
                duckManager, config, embeddedDnsServer, dockerHostResolver, MAPPER);

        client.execute("SELECT 1", null, "s3://floci-athena-results/results/q1/results.csv");

        String raw = capturedExecuteBody.get();
        assertNotNull(raw, "FlociDuckClient must POST to /execute");
        JsonNode json = MAPPER.readTree(raw);
        assertTrue(json.path("s3_access_key").isMissingNode() || json.path("s3_access_key").asText().isEmpty(),
                "/execute body must omit operator s3_access_key under IAM enforcement");
        assertTrue(json.path("s3_secret_key").isMissingNode() || json.path("s3_secret_key").asText().isEmpty(),
                "/execute body must omit operator s3_secret_key under IAM enforcement");
        assertNotEquals(operatorCreds.get("AWS_ACCESS_KEY_ID"), json.path("s3_access_key").asText(""));
        assertNotEquals(operatorCreds.get("AWS_SECRET_ACCESS_KEY"), json.path("s3_secret_key").asText(""));
    }

    @Test
    void athenaMockFalseUnderEnforcementFailsClosedWithoutDuck() {
        when(athenaConfig.mock()).thenReturn(false);
        when(iamConfig.enforcementEnabled()).thenReturn(true);

        AthenaService service = new AthenaService(
                storageFactory, duckClientMock, glueService, s3Service, config, vertx);

        String queryId = service.startQueryExecution(
                "SELECT * FROM secret_table", "primary", null, null);
        assertNotNull(queryId);

        QueryExecution execution = service.getQueryExecution(queryId);
        assertEquals(QueryExecutionState.FAILED, execution.getStatus().getState());
        assertTrue(execution.getStatus().getStateChangeReason().contains("IAM enforcement"),
                execution.getStatus().getStateChangeReason());

        verify(duckClientMock, never()).execute(anyString(), any(), anyString());
        verify(duckClientMock, never()).execute(anyString(), any(), anyString(), any());
    }

    private void startCaptureServer() throws IOException {
        captureServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        captureServer.createContext("/execute", exchange -> {
            byte[] req = exchange.getRequestBody().readAllBytes();
            capturedExecuteBody.set(new String(req, StandardCharsets.UTF_8));
            byte[] resp = "{\"status\":\"success\"}".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, resp.length);
            exchange.getResponseBody().write(resp);
            exchange.close();
        });
        captureServer.start();
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + captureServer.getAddress().getPort();
    }
}
