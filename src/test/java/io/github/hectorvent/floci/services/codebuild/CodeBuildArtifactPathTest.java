package io.github.hectorvent.floci.services.codebuild;

import io.github.hectorvent.floci.core.common.AwsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CodeBuildArtifactPathTest {

    @TempDir
    Path tempDir;

    @Test
    void rejectsBaseDirectoryOutsideWorkspace() {
        assertThrows(AwsException.class, () ->
                CodeBuildRunner.collectArtifactFiles(tempDir.resolve("workspace"),
                        tempDir.resolve("outside"), List.of("report.txt")));
    }

    @Test
    void rejectsEscapingArtifactPattern() {
        Path workspace = tempDir.resolve("workspace");

        assertThrows(AwsException.class, () ->
                CodeBuildRunner.collectArtifactFiles(workspace, workspace, List.of("../outside.txt")));
    }

    @Test
    void collectsFilesInsideWorkspace() throws Exception {
        Path workspace = tempDir.resolve("workspace");
        Files.createDirectories(workspace);
        Files.writeString(workspace.resolve("report.txt"), "report");

        List<Path> files = CodeBuildRunner.collectArtifactFiles(workspace, workspace, List.of("report.txt"));

        assertEquals(List.of(workspace.resolve("report.txt").toAbsolutePath().normalize()), files);
    }
}
