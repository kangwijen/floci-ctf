package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PathSandboxTest {

    @TempDir
    Path tempDir;

    @Test
    void normalizesToAbsolutePath() {
        Path relative = tempDir.relativize(tempDir.resolve("nested").resolve("..").resolve("workspace"));

        assertEquals(relative.toAbsolutePath().normalize(), PathSandbox.normalize(relative));
    }

    @Test
    void identifiesPathsInsideNormalizedRoot() {
        Path root = tempDir.resolve("workspace");

        assertTrue(PathSandbox.isContained(root, root.resolve("output").resolve("..").resolve("artifact.txt")));
        assertFalse(PathSandbox.isContained(root, root.resolve("..").resolve("outside.txt")));
    }

    @Test
    void rejectsPathOutsideRoot() {
        Path root = tempDir.resolve("workspace");

        AwsException exception = assertThrows(AwsException.class, () ->
                PathSandbox.requireContained(root, root.resolve("..").resolve("outside.txt"),
                        "InvalidPath", "Path must remain in the sandbox."));

        assertEquals("InvalidPath", exception.getErrorCode());
        assertEquals(400, exception.getHttpStatus());
    }
}
