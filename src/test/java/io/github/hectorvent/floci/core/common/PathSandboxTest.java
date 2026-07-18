package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
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

    @Test
    @Tag("security-regression")
    void rejectsSymlinkEscapeUnderAllowedRoot() throws IOException {
        Path allowed = Files.createDirectories(tempDir.resolve("allowed"));
        Path outside = Files.createDirectories(tempDir.resolve("outside"));
        Path secret = Files.writeString(outside.resolve("secret.txt"), "leak");
        Path link;
        try {
            link = Files.createSymbolicLink(allowed.resolve("escape"), outside);
        } catch (UnsupportedOperationException | IOException e) {
            Assumptions.assumeTrue(false, "symbolic links unavailable: " + e.getMessage());
            return;
        }

        Path escaped = link.resolve("secret.txt");
        assertTrue(Files.isRegularFile(escaped) || Files.isRegularFile(secret));
        assertFalse(PathSandbox.isContained(allowed, escaped),
                "symlink under allowed root must not count as contained when real path escapes");

        AwsException exception = assertThrows(AwsException.class, () ->
                PathSandbox.requireContained(allowed, escaped, "InvalidPath", "Path must remain in the sandbox."));
        assertEquals("InvalidPath", exception.getErrorCode());
    }

    @Test
    @Tag("security-regression")
    void allowsRealPathStillInsideRoot() throws IOException {
        Path root = Files.createDirectories(tempDir.resolve("workspace"));
        Path nested = Files.createDirectories(root.resolve("nested"));
        Path file = Files.writeString(nested.resolve("artifact.txt"), "ok");

        assertTrue(PathSandbox.isContained(root, file));
        assertEquals(file.toRealPath().normalize(),
                PathSandbox.requireContained(root, file, "InvalidPath", "Path must remain in the sandbox."));
    }
}
