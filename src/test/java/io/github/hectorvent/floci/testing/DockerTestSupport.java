package io.github.hectorvent.floci.testing;

/**
 * Shared helpers for integration tests that require a local Docker daemon.
 */
public final class DockerTestSupport {

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
}
