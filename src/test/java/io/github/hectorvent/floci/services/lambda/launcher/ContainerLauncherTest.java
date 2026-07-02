package io.github.hectorvent.floci.services.lambda.launcher;

import io.github.hectorvent.floci.config.EmulatorConfig;
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
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryManager;
import io.github.hectorvent.floci.services.lambda.container.LambdaContainerCredentialsServer;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.runtime.RuntimeApiServer;
import io.github.hectorvent.floci.services.lambda.runtime.RuntimeApiServerFactory;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.CopyArchiveToContainerCmd;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ContainerLauncherTest {

    @Mock ContainerLifecycleManager lifecycleManager;
    @Mock ContainerLogStreamer logStreamer;
    @Mock ImageResolver imageResolver;
    @Mock RuntimeApiServerFactory runtimeApiServerFactory;
    @Mock DockerHostResolver dockerHostResolver;
    @Mock EmulatorConfig config;
    @Mock EmulatorConfig.CtfConfig ctf;
    @Mock EcrRegistryManager ecrRegistryManager;
    @Mock EmbeddedDnsServer embeddedDnsServer;
    @Mock RuntimeApiServer runtimeApiServer;
    @Mock DockerClient dockerClient;
    @Mock LambdaContainerCredentialsServer credentialsServer;
    @Mock ContainerDetector containerDetector;
    @Mock CurrentContainerNetworkResolver currentContainerNetworkResolver;

    @TempDir
    Path tempDir;

    ContainerLauncher launcher;
    /** Collects remote paths passed to withRemotePath across all copy mocks. */
    final java.util.List<String> capturedRemotePaths = new java.util.ArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.LambdaServiceConfig lambda = mock(EmulatorConfig.LambdaServiceConfig.class);
        EmulatorConfig.DockerConfig docker = mock(EmulatorConfig.DockerConfig.class);

        when(config.services()).thenReturn(services);
        lenient().when(config.ctf()).thenReturn(ctf);
        lenient().when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(false);
        lenient().when(ctf.containerCredentialsLinkLocalHost()).thenReturn("169.254.170.2");
        when(services.lambda()).thenReturn(lambda);
        when(lambda.dockerNetwork()).thenReturn(Optional.empty());
        lenient().when(lambda.awsConfigPath()).thenReturn(Optional.empty());
        lenient().when(lambda.containerCredentialsPort()).thenReturn(9171);
        when(config.docker()).thenReturn(docker);
        when(docker.logMaxSize()).thenReturn("10m");
        when(docker.logMaxFile()).thenReturn("3");
        when(config.baseUrl()).thenReturn("http://localhost:4566");
        EmulatorConfig.TlsConfig tls = mock(EmulatorConfig.TlsConfig.class);
        when(config.tls()).thenReturn(tls);
        lenient().when(tls.enabled()).thenReturn(false);
        lenient().when(config.defaultRegion()).thenReturn("us-east-1");
        lenient().when(config.hostname()).thenReturn(Optional.empty());

        when(embeddedDnsServer.getServerIp()).thenReturn(Optional.empty());

        ContainerBuilder containerBuilder = new ContainerBuilder(config, dockerHostResolver, embeddedDnsServer);
        ContainerReachableEndpoint reachableEndpoint =
                new ContainerReachableEndpoint(config, dockerHostResolver, embeddedDnsServer);
        launcher = new ContainerLauncher(containerBuilder, lifecycleManager, logStreamer, imageResolver,
                runtimeApiServerFactory, dockerHostResolver, config, ecrRegistryManager,
                mock(io.github.hectorvent.floci.services.lambda.LambdaLayerService.class),
                credentialsServer, reachableEndpoint, containerDetector, currentContainerNetworkResolver);

        lenient().when(credentialsServer.registerFunction(any(), any(), any())).thenReturn(null);
        lenient().when(credentialsServer.injectRelativeUri()).thenReturn(false);

        when(runtimeApiServerFactory.create()).thenReturn(runtimeApiServer);
        when(runtimeApiServer.getPort()).thenReturn(9000);
        lenient().when(runtimeApiServer.stop()).thenReturn(CompletableFuture.completedFuture(null));
        when(dockerHostResolver.resolve()).thenReturn("127.0.0.1");

        when(lifecycleManager.create(any())).thenReturn("container-123");
        ContainerLifecycleManager.ContainerInfo info =
                new ContainerLifecycleManager.ContainerInfo("container-123", Map.of());
        when(lifecycleManager.startCreated(eq("container-123"), any())).thenReturn(info);
        lenient().doReturn(new ContainerExecResult(0, ""))
                .when(lifecycleManager).execForResult(any(), any(), anyInt());
        when(lifecycleManager.getDockerClient()).thenReturn(dockerClient);

        // Stub the Docker copy chain so copyDirToContainer / copyFileToContainer
        // don't throw when the mock DockerClient is used. Each invocation
        // returns a fresh mock that drains the tar InputStream on exec() to
        // prevent the background PipedOutputStream writer thread from blocking
        // when the pipe buffer fills.
        capturedRemotePaths.clear();
        lenient().when(dockerClient.copyArchiveToContainerCmd(any())).thenAnswer(inv -> {
            CopyArchiveToContainerCmd cmd = mock(CopyArchiveToContainerCmd.class);
            final java.io.InputStream[] captured = {null};
            when(cmd.withRemotePath(any())).thenAnswer(pathInv -> {
                capturedRemotePaths.add(pathInv.getArgument(0));
                return cmd;
            });
            when(cmd.withTarInputStream(any())).thenAnswer(streamInv -> {
                captured[0] = streamInv.getArgument(0);
                return cmd;
            });
            doAnswer(execInv -> {
                if (captured[0] != null) {
                    try { captured[0].transferTo(java.io.OutputStream.nullOutputStream()); }
                    catch (Exception ignored) {}
                }
                return null;
            }).when(cmd).exec();
            return cmd;
        });
    }

    @Test
    void launchFunction_createsWithoutBindMounts() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("code"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("standard-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        ContainerSpec spec = specCaptor.getValue();
        assertTrue(spec.binds().isEmpty(), "Function should NOT have bind mounts");
    }

    @Test
    void launchFunction_createsBeforeCopyAndStartsAfter() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("code"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("order-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        // Verify ordering: create → getDockerClient → Docker copy (to /var/task) → startCreated
        InOrder inOrder = inOrder(lifecycleManager, dockerClient);
        inOrder.verify(lifecycleManager).create(any());
        inOrder.verify(lifecycleManager).getDockerClient();
        inOrder.verify(dockerClient).copyArchiveToContainerCmd("container-123");
        inOrder.verify(lifecycleManager).startCreated(eq("container-123"), any());

        // createAndStart must NOT be called — Lambda uses the split path
        verify(lifecycleManager, never()).createAndStart(any());
    }

    @Test
    void launchFunction_injectsDefaultAwsCredentials() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("creds-defaults"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("creds-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        List<String> env = specCaptor.getValue().env();
        if (System.getenv("AWS_ACCESS_KEY_ID") != null) {
            assertTrue(env.stream().anyMatch(e -> e.startsWith("AWS_ACCESS_KEY_ID=")),
                    "AWS_ACCESS_KEY_ID should be injected when set in host env");
        }
        if (System.getenv("AWS_SECRET_ACCESS_KEY") != null) {
            assertTrue(env.stream().anyMatch(e -> e.startsWith("AWS_SECRET_ACCESS_KEY=")),
                    "AWS_SECRET_ACCESS_KEY should be injected when set in host env");
        }
        if (System.getenv("AWS_SESSION_TOKEN") != null) {
            assertTrue(env.stream().anyMatch(e -> e.startsWith("AWS_SESSION_TOKEN=")),
                    "AWS_SESSION_TOKEN should be injected when set in host env");
        }
    }

    @Test
    void launchFunction_omitsCredentialsWhenEnvUnset() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("creds-fallback"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("fallback-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        List<String> env = specCaptor.getValue().env();
        if (System.getenv("AWS_ACCESS_KEY_ID") == null) {
            assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_ACCESS_KEY_ID=")),
                    "AWS_ACCESS_KEY_ID should not be injected when unset");
        }
        if (System.getenv("AWS_SECRET_ACCESS_KEY") == null) {
            assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SECRET_ACCESS_KEY=")),
                    "AWS_SECRET_ACCESS_KEY should not be injected when unset");
        }
        if (System.getenv("AWS_SESSION_TOKEN") == null) {
            assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SESSION_TOKEN=")),
                    "AWS_SESSION_TOKEN should not be injected when unset");
        }
    }

    @Test
    void launchFunction_injectsConfiguredDefaultRegionWhenArnMissing() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("region-default"));
        when(config.defaultRegion()).thenReturn("eu-central-1");

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("region-default-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        List<String> env = specCaptor.getValue().env();
        assertTrue(env.contains("AWS_DEFAULT_REGION=eu-central-1"));
        assertTrue(env.contains("AWS_REGION=eu-central-1"));
    }

    @Test
    void launchFunction_injectsFunctionArnRegionForAwsSdkSigning() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("region-arn"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("region-arn-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());
        fn.setFunctionArn("arn:aws:lambda:eu-west-2:000000000000:function:region-arn-fn");

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        List<String> env = specCaptor.getValue().env();
        assertTrue(env.contains("AWS_DEFAULT_REGION=eu-west-2"));
        assertTrue(env.contains("AWS_REGION=eu-west-2"));
        verify(logStreamer).attach(
                eq("container-123"), any(), any(), eq("eu-west-2"), eq("lambda:region-arn-fn"));
    }

    @Test
    void launchFunction_userEnvironmentCannotInjectAwsCredentials() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("creds-override"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("override-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());
        fn.setEnvironment(Map.of(
                "AWS_ACCESS_KEY_ID", "user-key",
                "AWS_SECRET_ACCESS_KEY", "user-secret",
                "CUSTOM_APP_VAR", "sample-value"));

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        List<String> env = specCaptor.getValue().env();
        assertTrue(env.contains("CUSTOM_APP_VAR=sample-value"));
        assertFalse(env.stream().anyMatch(e -> e.equals("AWS_ACCESS_KEY_ID=user-key")));
        assertFalse(env.stream().anyMatch(e -> e.equals("AWS_SECRET_ACCESS_KEY=user-secret")));
    }

    @Test
    void launchImageFunction_rewritesAwsEcrUriUsingRegistryManagerHostnameStyle() {
        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("image-fn");
        fn.setPackageType("Image");
        fn.setImageUri("123456789012.dkr.ecr.us-east-1.amazonaws.com/backend-user:1");

        when(ecrRegistryManager.getRepositoryUri("123456789012", "us-east-1", "backend-user:1"))
                .thenReturn("123456789012.dkr.ecr.us-east-1.localhost:5100/backend-user:1");

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());
        verify(ecrRegistryManager).ensureStarted();
        verify(ecrRegistryManager).getRepositoryUri("123456789012", "us-east-1", "backend-user:1");
        assertEquals("123456789012.dkr.ecr.us-east-1.localhost:5100/backend-user:1",
                specCaptor.getValue().image());
    }

    @Test
    void launchImageFunction_rewritesAwsEcrUriUsingRegistryManagerPathStyle() {
        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("image-path-fn");
        fn.setPackageType("Image");
        fn.setImageUri("123456789012.dkr.ecr.us-east-1.amazonaws.com/backend-user:1");

        when(ecrRegistryManager.getRepositoryUri("123456789012", "us-east-1", "backend-user:1"))
                .thenReturn("localhost:5100/123456789012/us-east-1/backend-user:1");

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());
        verify(ecrRegistryManager).ensureStarted();
        verify(ecrRegistryManager).getRepositoryUri("123456789012", "us-east-1", "backend-user:1");
        assertEquals("localhost:5100/123456789012/us-east-1/backend-user:1",
                specCaptor.getValue().image());
    }

    @Test
    void launchProvidedRuntime_copiesBootstrapBeforeStart() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("provided-code"));
        Files.writeString(codePath.resolve("bootstrap"), "#!/bin/sh\necho hello");

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("provided-fn");
        fn.setRuntime("provided.al2023");
        fn.setHandler("bootstrap");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        // The critical invariant: create must happen before any Docker copy,
        // and start must happen after. This is the exact regression from #466.
        InOrder inOrder = inOrder(lifecycleManager, dockerClient);
        inOrder.verify(lifecycleManager).create(any());
        inOrder.verify(lifecycleManager).getDockerClient();
        // Two copies: code to /var/task + bootstrap to /var/runtime
        inOrder.verify(dockerClient, times(2)).copyArchiveToContainerCmd("container-123");
        inOrder.verify(lifecycleManager).startCreated(eq("container-123"), any());

        // Verify both /var/task and /var/runtime were targeted
        assertTrue(capturedRemotePaths.contains("/var/task"),
                "code should be copied to /var/task");
        assertTrue(capturedRemotePaths.contains("/var/runtime"),
                "bootstrap should be copied to /var/runtime");

        verify(lifecycleManager, never()).createAndStart(any());
    }

    @Test
    void launchFunction_awsConfigPath_bindsAndSkipsCredentials() throws Exception {
        EmulatorConfig.LambdaServiceConfig lambda = config.services().lambda();
        when(lambda.awsConfigPath()).thenReturn(Optional.of("/home/user/.aws"));

        Path codePath = Files.createDirectory(tempDir.resolve("creds-mount"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("mount-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        ContainerSpec spec = specCaptor.getValue();

        // Should bind-mount to /opt/aws-config (read-only)
        assertTrue(spec.binds().stream()
                        .anyMatch(b -> b.getPath().equals("/home/user/.aws")
                                && b.getVolume().getPath().equals("/opt/aws-config")
                                && b.getAccessMode() == com.github.dockerjava.api.model.AccessMode.ro),
                "awsConfigPath should be bind-mounted read-only to /opt/aws-config");

        // Should set explicit file paths for SDK discovery
        List<String> env = spec.env();
        assertTrue(env.contains("AWS_SHARED_CREDENTIALS_FILE=/opt/aws-config/credentials"),
                "AWS_SHARED_CREDENTIALS_FILE should point to mounted path");
        assertTrue(env.contains("AWS_CONFIG_FILE=/opt/aws-config/config"),
                "AWS_CONFIG_FILE should point to mounted path");

        // Should NOT inject credential env vars
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_ACCESS_KEY_ID=")),
                "AWS_ACCESS_KEY_ID should not be injected when awsConfigPath is set");
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SECRET_ACCESS_KEY=")),
                "AWS_SECRET_ACCESS_KEY should not be injected when awsConfigPath is set");
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SESSION_TOKEN=")),
                "AWS_SESSION_TOKEN should not be injected when awsConfigPath is set");
    }

    @Test
    void launchFunction_noAwsConfigPath_noBindMount() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("no-aws-config"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("no-mount-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        assertTrue(specCaptor.getValue().binds().stream()
                        .noneMatch(b -> b.getVolume().getPath().equals("/opt/aws-config")),
                "no .aws bind mount when awsConfigPath is absent");
    }

    @Test
    void launchFunction_withExecutionRole_injectsContainerCredentialsUri() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("exec-role"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("exec-role-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());
        fn.setRole("arn:aws:iam::000000000000:role/lambda-exec");

        when(credentialsServer.registerFunction(
                eq("exec-role-fn"),
                eq("arn:aws:iam::000000000000:role/lambda-exec"),
                eq("us-east-1"))).thenReturn("cred-token-1");
        when(credentialsServer.credentialsFullUri("127.0.0.1", "cred-token-1"))
                .thenReturn("http://127.0.0.1:9171/v2/credentials/cred-token-1");

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());

        List<String> env = specCaptor.getValue().env();
        assertTrue(env.contains("AWS_CONTAINER_CREDENTIALS_FULL_URI=http://127.0.0.1:9171/v2/credentials/cred-token-1"));
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=")),
                "RELATIVE_URI must not be set on non-80 credential ports (botocore would use link-local :80)");
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_ACCESS_KEY_ID=")),
                "operator credentials must not be injected when execution role is set");
        assertTrue(env.stream().noneMatch(e -> e.startsWith("AWS_SECRET_ACCESS_KEY=")),
                "operator credentials must not be injected when execution role is set");
    }

    @Test
    void launchFunction_withExecutionRole_skipsLinkLocalExtraHostWhenFlociInDocker() throws Exception {
        when(ctf.containerCredentialsUseLinkLocalUri()).thenReturn(true);
        when(containerDetector.isRunningInContainer()).thenReturn(true);

        Path codePath = Files.createDirectory(tempDir.resolve("link-local-creds"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("link-local-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());
        fn.setRole("arn:aws:iam::000000000000:role/lambda-exec");

        when(credentialsServer.registerFunction(any(), any(), any())).thenReturn("cred-token-link");
        when(credentialsServer.credentialsFullUri("127.0.0.1", "cred-token-link"))
                .thenReturn("http://127.0.0.1:9171/v2/credentials/cred-token-link");

        launcher.launch(fn);

        ArgumentCaptor<ContainerSpec> specCaptor = ArgumentCaptor.forClass(ContainerSpec.class);
        verify(lifecycleManager).create(specCaptor.capture());
        assertTrue(specCaptor.getValue().extraHosts().stream()
                        .noneMatch(h -> h.startsWith("169.254.170.2:")),
                "link-local extra_hosts are not used when Floci runs inside Docker");
        assertTrue(specCaptor.getValue().env().stream()
                        .noneMatch(e -> e.startsWith("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=")),
                "link-local FULL_URI must be used without RELATIVE_URI on port 9171");
    }

    @Test
    void stopFunction_unregistersExecutionRoleCredentials() throws Exception {
        Path codePath = Files.createDirectory(tempDir.resolve("stop-creds"));

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("stop-creds-fn");
        fn.setRuntime("nodejs20.x");
        fn.setHandler("index.handler");
        fn.setCodeLocalPath(codePath.toString());
        fn.setRole("arn:aws:iam::000000000000:role/lambda-exec");

        when(credentialsServer.registerFunction(any(), any(), any())).thenReturn("cred-token-stop");
        when(credentialsServer.credentialsFullUri(any(), eq("cred-token-stop")))
                .thenReturn("http://127.0.0.1:9171/v2/credentials/cred-token-stop");

        ContainerHandle handle = launcher.launch(fn);
        launcher.stop(handle);

        verify(credentialsServer).unregisterFunction(
                eq("stop-creds-fn"), eq(java.util.List.of("cred-token-stop")));
    }
}
