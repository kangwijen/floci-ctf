package io.github.hectorvent.floci.testing;

import java.nio.file.Path;

/**
 * Cross-platform helpers for TLS integration tests.
 */
public final class TlsTestSupport {

    private TlsTestSupport() {
    }

    public static Path tempDir(String name) {
        return Path.of(System.getProperty("java.io.tmpdir"), name);
    }

    /**
     * Path string safe for MicroProfile config: forward slashes avoid backslash
     * escape mangling (e.g. {@code \t}, {@code \f}) on Windows.
     */
    public static String configPath(Path path) {
        return path.toAbsolutePath().normalize().toString().replace('\\', '/');
    }
}
