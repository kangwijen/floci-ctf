package io.github.hectorvent.floci.services.ecs.container;

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

class EcsContainerCredentialsServerTest {

    private Vertx vertx;
    private EcsContainerCredentialsServer server;
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
        EmulatorConfig.EcsServiceConfig ecs = mock(EmulatorConfig.EcsServiceConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        when(config.services()).thenReturn(services);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.containerCredentialsBindLocalhost()).thenReturn(true);
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(false);
        when(services.ecs()).thenReturn(ecs);
        when(config.defaultAccountId()).thenReturn("000000000000");
        port = findFreePort();
        when(ecs.containerCredentialsPort()).thenReturn(port);

        iamService = mock(IamService.class);
        IamRole role = new IamRole();
        role.setRoleName("ecs-task-role");
        role.setArn("arn:aws:iam::000000000000:role/ecs-task-role");
        role.setRoleId("AROA123");
        when(iamService.getRoleByArn("arn:aws:iam::000000000000:role/ecs-task-role")).thenReturn(role);

        server = new EcsContainerCredentialsServer(vertx, config, iamService);
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
        String token = server.registerTask(
                "arn:aws:ecs:us-east-1:000000000000:task/cluster/abc123",
                "abc123",
                "arn:aws:iam::000000000000:role/ecs-task-role",
                "my-family",
                "us-east-1");

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/v2/credentials/" + token))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"AccessKeyId\":\"ASIA"));
        assertTrue(response.body().contains("\"RoleArn\":\"arn:aws:iam::000000000000:role/ecs-task-role\""));
        verify(iamService).registerSession(anyString(), eq("arn:aws:iam::000000000000:role/ecs-task-role"),
                any(Instant.class), isNull(), anyString(), anyString(), anyString(), isNull(), anyString());
    }

    @Test
    @Timeout(15)
    void metadataEndpointReturnsTaskRoleArn() throws Exception {
        server.registerTask(
                "arn:aws:ecs:us-east-1:000000000000:task/cluster/task-42",
                "task-42",
                "arn:aws:iam::000000000000:role/ecs-task-role",
                "my-family",
                "us-east-1");

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/v4/task-42"))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"TaskARN\":\"arn:aws:ecs:us-east-1:000000000000:task/cluster/task-42\""));
        assertTrue(response.body().contains("\"TaskRoleArn\":\"arn:aws:iam::000000000000:role/ecs-task-role\""));
    }

    @Test
    @Timeout(15)
    void unregisterTaskRemovesCredentials() throws Exception {
        String token = server.registerTask(
                "arn:aws:ecs:us-east-1:000000000000:task/cluster/stop-me",
                "stop-me",
                "arn:aws:iam::000000000000:role/ecs-task-role",
                "my-family",
                "us-east-1");
        server.unregisterTask("stop-me", java.util.List.of(token));

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/v2/credentials/" + token))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(404, response.statusCode());
    }

    private static int findFreePort() throws Exception {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
