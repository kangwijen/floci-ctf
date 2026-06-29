package io.github.hectorvent.floci.testsupport;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;

/**
 * CTF Compose parity plus dedicated container credential ports for integration tests.
 */
public class LambdaContainerCredentialsIamProfile extends CtfComposeParityProfile {

    public static final int LAMBDA_CREDS_PORT = findFreePort();
    public static final int ECS_CREDS_PORT = findFreePort();
    public static final int CODEBUILD_CREDS_PORT = findFreePort();

    private static int findFreePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new IllegalStateException("Could not allocate free port for container credentials test", e);
        }
    }

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> overrides = new HashMap<>(super.getConfigOverrides());
        overrides.put("floci.services.lambda.container-credentials-port", String.valueOf(LAMBDA_CREDS_PORT));
        overrides.put("floci.services.ecs.container-credentials-port", String.valueOf(ECS_CREDS_PORT));
        overrides.put("floci.services.ecs.mock", "false");
        overrides.put("floci.services.codebuild.container-credentials-port", String.valueOf(CODEBUILD_CREDS_PORT));
        // Host-side @QuarkusTest fetches creds via 127.0.0.1; link-local URIs are for Docker workloads.
        overrides.put("floci.ctf.container-credentials-use-link-local-uri", "false");
        overrides.put("floci.ctf.container-credentials-bind-localhost", "true");
        return overrides;
    }
}
