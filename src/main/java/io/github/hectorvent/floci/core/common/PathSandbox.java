package io.github.hectorvent.floci.core.common;

import java.nio.file.Path;

public final class PathSandbox {

    private PathSandbox() {
    }

    public static Path normalize(Path path) {
        return path.toAbsolutePath().normalize();
    }

    public static boolean isContained(Path root, Path candidate) {
        return normalize(candidate).startsWith(normalize(root));
    }

    public static Path requireContained(Path root, Path candidate, String errorCode, String message) {
        Path normalizedCandidate = normalize(candidate);
        if (!normalizedCandidate.startsWith(normalize(root))) {
            throw new AwsException(errorCode, message, 400);
        }
        return normalizedCandidate;
    }
}
