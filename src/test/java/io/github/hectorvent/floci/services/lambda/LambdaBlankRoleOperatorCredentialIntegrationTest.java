package io.github.hectorvent.floci.services.lambda;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.OperatorCredentialEnv;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.container.ContainerCredentialsHttpServer;
import io.github.hectorvent.floci.core.common.dns.EmbeddedDnsServer;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerExecResult;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.ContainerReachableEndpoint;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import io.github.hectorvent.floci.core.common.docker.CurrentContainerNetworkResolver;
import io.github.hectorvent.floci.core.common.docker.DockerHostResolver;
import io.github.hectorvent.floci.core.common.docker.LaunchedContainerAwsEnv;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryManager;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.lambda.container.LambdaContainerCredentialsServer;
import io.github.hectorvent.floci.services.lambda.launcher.ContainerLauncher;
import io.github.hectorvent.floci.services.lambda.launcher.ImageResolver;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.runtime.RuntimeApiServer;
import io.github.hectorvent.floci.services.lambda.runtime.RuntimeApiServerFactory;
import io.github.hectorvent.floci.services.lambda.zip.CodeStore;
import io.github.hectorvent.floci.services.lambda.zip.ZipExtractor;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CopyArchiveToContainerCmd;
import io.vertx.core.Vertx;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Regression for VULN-2: UpdateFunctionConfiguration must reject blank Role,
 * and ContainerLauncher must not inject OperatorCredentialEnv under IAM enforcement.
 */
@ExtendWith(MockitoExtension.class)
class LambdaBlankRoleOperatorCredentialIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/lambda-exec";

    @Mock ContainerLifecycleManager lifecycleManager;
    @Mock ContainerLogStreamer logStreamer;
    @Mock ImageResolver imageResolver;
    @Mock RuntimeApiServerFactory runtimeApiServerFactory;
    @Mock DockerHostResolver dockerHostResolver;
    @Mock EmulatorConfig config;
    @Mock EmulatorConfig.CtfConfig ctf;
    @Mock EmulatorConfig.IamServiceConfig iam;
    @Mock EcrRegistryManager ecrRegistryManager;
    @Mock EmbeddedDnsServer embeddedDnsServer;
    @Mock RuntimeApiServer runtimeApiServer;
    @Mock DockerClient dockerClient;
    @Mock LambdaContainerCredentialsServer credentialsServer;
    @Mock ContainerDetector containerDetector;
    @Mock CurrentContainerNetworkResolver currentContainerNetworkResolver;
    @Mock IamService iamService;

    @TempDir
    Path tempDir;

    private LambdaService lambdaService;
    private ContainerLauncher launcher;
    private ContainerCredentialsHttpServer credentialsHttpServer;

    @BeforeEach
    void setUp() throws Exception {
        LambdaFunctionStore store = new LambdaFunctionStore(new InMemoryStorage<>());
        WarmPool warmPool = new WarmPool();
        CodeStore codeStore = new CodeStore(Path.of("target/test-data/lambda-blank-role"));
        ZipExtractor zipExtractor = new ZipExtractor();
        RegionResolver regionResolver = new RegionResolver("us-east-1", "000000000000");
        lambdaService = new LambdaService(store, warmPool, codeStore, zipExtractor, regionResolver);

        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.LambdaServiceConfig lambda = mock(EmulatorConfig.LambdaServiceConfig.class);
        EmulatorConfig.DockerConfig docker = mock(EmulatorConfig.DockerConfig.class);
        EmulatorConfig.TlsConfig tls = mock(EmulatorConfig.TlsConfig.class);

        lenient().when(config.services()).thenReturn(services);
        lenient().when(config.ctf()).thenReturn(ctf);
        lenient().when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(false);
        lenient().when(ctf.containerCredentialsLinkLocalHost()).thenReturn("169.254.170.2");
        lenient().when(services.lambda()).thenReturn(lambda);
        lenient().when(services.iam()).thenReturn(iam);
        lenient().when(iam.enforcementEnabled()).thenReturn(true);
        lenient().when(lambda.dockerNetwork()).thenReturn(Optional.empty());
        lenient().when(lambda.awsConfigPath()).thenReturn(Optional.empty());
        lenient().when(lambda.containerCredentialsPort()).thenReturn(9171);
        lenient().when(config.docker()).thenReturn(docker);
        lenient().when(docker.logMaxSize()).thenReturn("10m");
        lenient().when(docker.logMaxFile()).thenReturn("3");
        lenient().when(config.baseUrl()).thenReturn("http://localhost:4566");
        lenient().when(config.tls()).thenReturn(tls);
        lenient().when(tls.enabled()).thenReturn(false);
        lenient().when(config.defaultRegion()).thenReturn("us-east-1");
        lenient().when(config.hostname()).thenReturn(Optional.empty());
        lenient().when(embeddedDnsServer.getServerIp()).thenReturn(Optional.empty());

        credentialsHttpServer = new ContainerCredentialsHttpServer(
                Vertx.vertx(), config, iamService, () -> 9171, "Lambda-BlankRole", containerDetector);

        lenient().when(credentialsServer.registerFunction(any(), any(), any())).thenAnswer(inv ->
                credentialsHttpServer.register(inv.getArgument(0), inv.getArgument(1), inv.getArgument(2)));
        lenient().when(credentialsServer.injectRelativeUri()).thenReturn(false);

        ContainerBuilder containerBuilder = new ContainerBuilder(config, dockerHostResolver, embeddedDnsServer);
        ContainerReachableEndpoint reachableEndpoint =
                new ContainerReachableEndpoint(config, dockerHostResolver, embeddedDnsServer);
        LaunchedContainerAwsEnv awsEnv = new LaunchedContainerAwsEnv(reachableEndpoint);
        launcher = new ContainerLauncher(containerBuilder, lifecycleManager, logStreamer, imageResolver,
                runtimeApiServerFactory, dockerHostResolver, config, ecrRegistryManager,
                mock(LambdaLayerService.class),
                credentialsServer, reachableEndpoint, containerDetector, currentContainerNetworkResolver,
                awsEnv, null);

        lenient().when(runtimeApiServerFactory.create()).thenReturn(runtimeApiServer);
        lenient().when(runtimeApiServer.getPort()).thenReturn(9000);
        lenient().when(runtimeApiServer.stop()).thenReturn(CompletableFuture.completedFuture(null));
        lenient().when(dockerHostResolver.resolve()).thenReturn("127.0.0.1");
        lenient().when(lifecycleManager.create(any())).thenReturn("container-blank-role");
        ContainerLifecycleManager.ContainerInfo info =
                new ContainerLifecycleManager.ContainerInfo("container-blank-role", Map.of());
        lenient().when(lifecycleManager.startCreated(eq("container-blank-role"), any())).thenReturn(info);
        lenient().doReturn(new ContainerExecResult(0, ""))
                .when(lifecycleManager).execForResult(any(), any(), anyInt());
        lenient().when(lifecycleManager.getDockerClient()).thenReturn(dockerClient);

        lenient().when(dockerClient.copyArchiveToContainerCmd(any())).thenAnswer(inv -> {
            CopyArchiveToContainerCmd cmd = mock(CopyArchiveToContainerCmd.class);
            final java.io.InputStream[] captured = {null};
            when(cmd.withRemotePath(any())).thenReturn(cmd);
            when(cmd.withTarInputStream(any())).thenAnswer(streamInv -> {
                captured[0] = streamInv.getArgument(0);
                return cmd;
            });
            doAnswer(execInv -> {
                if (captured[0] != null) {
                    try {
                        captured[0].transferTo(java.io.OutputStream.nullOutputStream());
                    } catch (Exception ignored) {
                    }
                }
                return null;
            }).when(cmd).exec();
            return cmd;
        });
    }

    @Test
    void updateFunctionConfiguration_blankRole_rejected() {
        Map<String, Object> createReq = new HashMap<>();
        createReq.put("FunctionName", "blank-role-fn");
        createReq.put("Runtime", "nodejs20.x");
        createReq.put("Role", ROLE_ARN);
        createReq.put("Handler", "index.handler");
        createReq.put("Timeout", 10);
        createReq.put("MemorySize", 256);
        LambdaFunction created = lambdaService.createFunction(REGION, createReq);
        assertEquals(ROLE_ARN, created.getRole());

        AwsException thrown = assertThrows(AwsException.class, () ->
                lambdaService.updateFunctionConfiguration(REGION, "blank-role-fn", Map.of("Role", "")));
        assertEquals(400, thrown.getHttpStatus());
        assertEquals("InvalidParameterValueException", thrown.getErrorCode());
        assertTrue(thrown.getMessage().contains("Role"));

        AwsException whitespace = assertThrows(AwsException.class, () ->
                lambdaService.updateFunctionConfiguration(REGION, "blank-role-fn", Map.of("Role", "   ")));
        assertEquals(400, whitespace.getHttpStatus());

        LambdaFunction unchanged = lambdaService.getFunction(REGION, "blank-role-fn");
        assertEquals(ROLE_ARN, unchanged.getRole());
    }

    @Test
    void launch_underIamEnforcement_doesNotInjectOperatorCredentialsForBlankRole() throws Exception {
        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("blank-role-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setRole("");
        fn.setFunctionArn("arn:aws:lambda:us-east-1:000000000000:function:blank-role-fn");
        Path codePath = Files.createDirectory(tempDir.resolve("code"));
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<String> roleCaptor = ArgumentCaptor.forClass(String.class);
        verify(credentialsServer).registerFunction(eq("blank-role-fn"), roleCaptor.capture(), eq(REGION));
        assertTrue(roleCaptor.getValue() == null || roleCaptor.getValue().isBlank());

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());
        List<String> env = specCaptor.getValue().env();

        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_CONTAINER_CREDENTIALS_FULL_URI=")));
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=")));
        assertFalse(env.stream().anyMatch(e -> e.startsWith("AWS_ACCESS_KEY_ID=")),
                "IAM enforcement must not inject operator AWS_ACCESS_KEY_ID for blank role");
        assertFalse(env.stream().anyMatch(e -> e.startsWith("AWS_SECRET_ACCESS_KEY=")),
                "IAM enforcement must not inject operator AWS_SECRET_ACCESS_KEY for blank role");

        List<String> operatorProbe = new java.util.ArrayList<>();
        OperatorCredentialEnv.addIfPresent(operatorProbe);
        for (String entry : operatorProbe) {
            assertFalse(env.contains(entry),
                    "ContainerLauncher must not inject OperatorCredentialEnv under enforcement: " + entry);
        }
    }
}
