package io.github.hectorvent.floci.services.codebuild.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.container.ContainerCredentialsHttpServer;
import io.github.hectorvent.floci.services.iam.IamService;
import io.vertx.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * CodeBuild build container credentials HTTP server on the Floci host.
 * Build containers receive {@code AWS_CONTAINER_CREDENTIALS_FULL_URI} pointing here when
 * the project has a service role configured.
 */
@ApplicationScoped
public class CodeBuildContainerCredentialsServer {

    private final ContainerCredentialsHttpServer delegate;

    @Inject
    public CodeBuildContainerCredentialsServer(Vertx vertx, EmulatorConfig config, IamService iamService) {
        this.delegate = new ContainerCredentialsHttpServer(
                vertx, config, iamService,
                () -> config.services().codebuild().containerCredentialsPort(),
                "CodeBuild");
    }

    public String registerBuild(String buildId, String serviceRoleArn, String region) {
        return delegate.register(buildId, serviceRoleArn, region);
    }

    public void unregisterBuild(String buildId, List<String> credentialTokens) {
        delegate.unregister(buildId, credentialTokens);
    }

    public String credentialsFullUri(String hostAddress, String credentialToken) {
        return delegate.credentialsFullUri(hostAddress, credentialToken);
    }

    public String credentialsRelativeUri(String credentialToken) {
        return delegate.credentialsRelativeUri(credentialToken);
    }

    public CompletableFuture<Void> start() {
        return delegate.start();
    }

    public void stop() {
        delegate.stop();
    }
}
