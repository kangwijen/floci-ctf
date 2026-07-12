package io.github.hectorvent.floci.fuzz.oracle;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Writes minimized findings under {@code tools/fuzz/findings/} for later graduation to {@code src/test}.
 */
public final class FindingSerializer {

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS").withZone(ZoneOffset.UTC);
    private static final AtomicInteger SEQ = new AtomicInteger();

    private FindingSerializer() {
    }

    public static Path findingsDir() {
        String override = System.getProperty("fuzz.findings.dir");
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return Path.of("findings");
    }

    public static Path write(Finding finding) throws IOException {
        Path dir = findingsDir();
        Files.createDirectories(dir);
        String name = TS.format(finding.recordedAt())
                + "-"
                + SEQ.incrementAndGet()
                + "-"
                + sanitize(finding.target())
                + "-"
                + finding.kind().name().toLowerCase()
                + ".txt";
        Path out = dir.resolve(name);
        StringBuilder sb = new StringBuilder();
        sb.append("kind=").append(finding.kind()).append('\n');
        sb.append("target=").append(finding.target()).append('\n');
        sb.append("summary=").append(finding.summary()).append('\n');
        sb.append("recordedAt=").append(finding.recordedAt()).append('\n');
        sb.append("seed=\n").append(finding.seed()).append('\n');
        sb.append("details=\n");
        for (Map.Entry<String, String> e : finding.details().entrySet()) {
            sb.append("  ").append(e.getKey()).append('=').append(e.getValue()).append('\n');
        }
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
        return out;
    }

    private static String sanitize(String target) {
        return target.replaceAll("[^A-Za-z0-9._-]+", "_");
    }
}
