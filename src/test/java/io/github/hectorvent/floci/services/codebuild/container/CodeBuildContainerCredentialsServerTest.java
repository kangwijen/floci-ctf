package io.github.hectorvent.floci.services.codebuild.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
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

class CodeBuildContainerCredentialsServerTest {

    private Vertx vertx;
    private CodeBuildContainerCredentialsServer server;
    private IamService iamService;
    private EmulatorConfig.CtfConfig ctf;
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
        EmulatorConfig.CodeBuildServiceConfig codebuild = mock(EmulatorConfig.CodeBuildServiceConfig.class);
        ctf = mock(EmulatorConfig.CtfConfig.class);
        when(config.services()).thenReturn(services);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.containerCredentialsBindLocalhost()).thenReturn(true);
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(false);
        when(services.codebuild()).thenReturn(codebuild);
        when(config.defaultAccountId()).thenReturn("000000000000");
        port = findFreePort();
        when(codebuild.containerCredentialsPort()).thenReturn(port);

        iamService = mock(IamService.class);
        IamRole role = new IamRole();
        role.setRoleName("codebuild-service-role");
        role.setArn("arn:aws:iam::000000000000:role/codebuild-service-role");
        role.setRoleId("AROA789");
        when(iamService.getRoleByArn("arn:aws:iam::000000000000:role/codebuild-service-role")).thenReturn(role);

        server = new CodeBuildContainerCredentialsServer(vertx, config, iamService, mock(ContainerDetector.class));
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
        String token = server.registerBuild(
                "my-build",
                "arn:aws:iam::000000000000:role/codebuild-service-role",
                "us-east-1");

        HttpResponse<String> response = httpClient.send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/v2/credentials/" + token))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode());
        assertTrue(response.body().contains("\"AccessKeyId\":\"ASIA"));
        assertTrue(response.body().contains("\"RoleArn\":\"arn:aws:iam::000000000000:role/codebuild-service-role\""));
        verify(iamService).registerSession(anyString(), eq("arn:aws:iam::000000000000:role/codebuild-service-role"),
                any(Instant.class), isNull(), anyString(), anyString(), anyString(), isNull(), anyString());
    }

    @Test
    @Timeout(15)
    void registerBuildReturnsNullWhenRoleMissing() {
        assertEquals(null, server.registerBuild("no-role-build", null, "us-east-1"));
        assertEquals(null, server.registerBuild("blank-role-build", "  ", "us-east-1"));
    }

    @Test
    @Timeout(15)
    void unregisterBuildRemovesCredentials() throws Exception {
        String token = server.registerBuild(
                "stop-me",
                "arn:aws:iam::000000000000:role/codebuild-service-role",
                "us-east-1");
        server.unregisterBuild("stop-me", java.util.List.of(token));

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

    @Test
    void credentialsRelativeUriReturnsPathOnly() {
        assertEquals("/v2/credentials/abc-token", server.credentialsRelativeUri("abc-token"));
    }

    @Test
    void credentialsFullUriUsesLinkLocalHostWhenEnabled() {
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(true);
        when(ctf.containerCredentialsLinkLocalHost()).thenReturn("169.254.170.2");
        assertEquals("http://169.254.170.2:" + port + "/v2/credentials/abc-token",
                server.credentialsFullUri("ignored-host", "abc-token"));
    }

    private static int findFreePort() throws Exception {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }
}
