package io.github.hectorvent.floci.core.common;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.Deque;

public final class PathSandbox {

    private PathSandbox() {
    }

    public static Path normalize(Path path) {
        return path.toAbsolutePath().normalize();
    }

    /**
     * Resolves symbolic links via {@link Path#toRealPath()} for the longest existing
     * prefix, then appends any missing leaf segments. Used before allowlist contains checks
     * so a symlink under an allowed root cannot escape to a disallowed real path.
     */
    public static Path resolveRealPath(Path path) throws IOException {
        Path absolute = normalize(path);
        Deque<Path> missing = new ArrayDeque<>();
        Path existing = absolute;
        while (existing != null && !Files.exists(existing)) {
            Path name = existing.getFileName();
            if (name != null) {
                missing.addFirst(name);
            }
            existing = existing.getParent();
        }
        if (existing == null) {
            return absolute;
        }
        Path real = existing.toRealPath();
        for (Path part : missing) {
            real = real.resolve(part);
        }
        return real.normalize();
    }

    public static boolean isContained(Path root, Path candidate) {
        try {
            return resolveRealPath(candidate).startsWith(resolveRealPath(root));
        } catch (IOException e) {
            return false;
        }
    }

    public static Path requireContained(Path root, Path candidate, String errorCode, String message) {
        try {
            Path realCandidate = resolveRealPath(candidate);
            if (!realCandidate.startsWith(resolveRealPath(root))) {
                throw new AwsException(errorCode, message, 400);
            }
            return realCandidate;
        } catch (IOException e) {
            throw new AwsException(errorCode, message, 400);
        }
    }
}
