package io.github.hectorvent.floci.services.lambda.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.container.ContainerCredentialsHttpServer;
import io.github.hectorvent.floci.services.iam.IamService;
import io.vertx.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Lambda execution environment credentials HTTP server bound to port 9171 on the Floci host.
 * Function containers receive {@code AWS_CONTAINER_CREDENTIALS_FULL_URI} pointing here when
 * the function has an execution role configured.
 */
@ApplicationScoped
public class LambdaContainerCredentialsServer {

    private final ContainerCredentialsHttpServer delegate;

    @Inject
    public LambdaContainerCredentialsServer(Vertx vertx, EmulatorConfig config, IamService iamService) {
        this.delegate = new ContainerCredentialsHttpServer(
                vertx, config, iamService,
                () -> config.services().lambda().containerCredentialsPort(),
                "Lambda");
    }

    public String registerFunction(String functionName, String executionRoleArn, String region) {
        return delegate.register(functionName, executionRoleArn, region);
    }

    public void unregisterFunction(String functionName, List<String> credentialTokens) {
        delegate.unregister(functionName, credentialTokens);
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
