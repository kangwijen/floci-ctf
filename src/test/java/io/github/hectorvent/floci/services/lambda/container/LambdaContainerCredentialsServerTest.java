package io.github.hectorvent.floci.services.lambda.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class LambdaContainerCredentialsServerTest {

    private Vertx vertx;
    private LambdaContainerCredentialsServer server;
    private IamService iamService;
    private HttpClient httpClient;
    private int port;

    @BeforeEach
    void setUp() throws Exception {
        vertx = Vertx.vertx();
        httpClient = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .build();

        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.LambdaServiceConfig lambda = mock(EmulatorConfig.LambdaServiceConfig.class);
        when(config.services()).thenReturn(services);
        when(services.lambda()).thenReturn(lambda);
        when(config.defaultAccountId()).thenReturn("000000000000");
        port = findFreePort();
        when(lambda.containerCredentialsPort()).thenReturn(port);

        iamService = mock(IamService.class);
        IamRole role = new IamRole();
        role.setRoleName("lambda-exec-role");
        role.setArn("arn:aws:iam::000000000000:role/lambda-exec-role");
        role.setRoleId("AROA456");
        when(iamService.getRoleByArn("arn:aws:iam::000000000000:role/lambda-exec-role")).thenReturn(role);

        server = new LambdaContainerCredentialsServer(vertx, config, iamService);
        server.start().get(5, TimeUnit.SECONDS);
    }

    @AfterEach
    void tearDown() throws Exception {
        server.stop();
        vertx.close();
    }

    @Test
    @Timeout(15)
    void credentialsEndpointReturnsTemporaryCredentials() throws Exception {
        String token = server.registerFunction(
                "my-function",
                "arn:aws:iam::000000000000:role/lambda-exec-role",
                "us-east-1");

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/v2/credentials/" + token))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"AccessKeyId\":\"ASIA"));
        assertTrue(response.body().contains("\"RoleArn\":\"arn:aws:iam::000000000000:role/lambda-exec-role\""));
        verify(iamService).registerSession(anyString(), eq("arn:aws:iam::000000000000:role/lambda-exec-role"),
                any(Instant.class), isNull(), anyString(), anyString(), anyString());
    }

    @Test
    @Timeout(15)
    void registerFunctionReturnsNullWhenRoleMissing() {
        assertEquals(null, server.registerFunction("no-role-fn", null, "us-east-1"));
        assertEquals(null, server.registerFunction("blank-role-fn", "  ", "us-east-1"));
    }

    @Test
    @Timeout(15)
    void unregisterFunctionRemovesCredentials() throws Exception {
        String token = server.registerFunction(
                "stop-me",
                "arn:aws:iam::000000000000:role/lambda-exec-role",
                "us-east-1");
        server.unregisterFunction("stop-me", java.util.List.of(token));

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/v2/credentials/" + token))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(404, response.statusCode());
    }

    @Test
    void credentialsFullUriUsesConfiguredPort() {
        String uri = server.credentialsFullUri("127.0.0.1", "abc-token");
        assertEquals("http://127.0.0.1:" + port + "/v2/credentials/abc-token", uri);
    }

    private static int findFreePort() throws Exception {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
