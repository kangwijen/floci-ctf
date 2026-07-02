package io.github.hectorvent.floci.testing;

import io.restassured.RestAssured;
import io.restassured.config.HttpClientConfig;

/**
 * Shared helpers for integration tests that require a local Docker daemon.
 */
public final class DockerTestSupport {

    /** HTTP timeouts for management calls that block on container image pull and readiness. */
    private static final int DOCKER_HTTP_TIMEOUT_MS = 180_000;

    private DockerTestSupport() {
    }

    public static boolean isDockerAvailable() {
        try {
            Process process = new ProcessBuilder("docker", "version", "--format", "{{.Server.Version}}")
                    .redirectErrorStream(true)
                    .start();
            int exit = process.waitFor();
            return exit == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * RestAssured defaults are too short for CreateDBCluster and similar actions that
     * pull images and wait for backend readiness inside the HTTP request thread.
     */
    public static void configureLongHttpTimeouts() {
        RestAssured.config = RestAssured.config()
                .httpClient(HttpClientConfig.httpClientConfig()
                        .setParam("http.connection.timeout", DOCKER_HTTP_TIMEOUT_MS)
                        .setParam("http.socket.timeout", DOCKER_HTTP_TIMEOUT_MS));
    }
}
