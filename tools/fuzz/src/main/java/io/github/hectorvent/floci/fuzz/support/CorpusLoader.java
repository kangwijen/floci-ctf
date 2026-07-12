package io.github.hectorvent.floci.fuzz.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Loads seed files from {@code tools/fuzz/corpora} (property {@code fuzz.corpora.dir}).
 */
public final class CorpusLoader {

    private CorpusLoader() {
    }

    public static Path corporaRoot() {
        String override = System.getProperty("fuzz.corpora.dir");
        if (override != null && !override.isBlank()) {
            return Path.of(override);
        }
        return Path.of("corpora");
    }

    public static List<String> lines(String relativePath) {
        Path file = corporaRoot().resolve(relativePath);
        if (!Files.isRegularFile(file)) {
            return List.of();
        }
        try {
            List<String> out = new ArrayList<>();
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    out.add(trimmed);
                }
            }
            return out;
        } catch (IOException e) {
            return List.of();
        }
    }

    public static List<String> filesUnder(String relativeDir) {
        Path dir = corporaRoot().resolve(relativeDir);
        if (!Files.isDirectory(dir)) {
            return List.of();
        }
        try (Stream<Path> walk = Files.list(dir)) {
            List<String> out = new ArrayList<>();
            walk.filter(Files::isRegularFile).sorted().forEach(p -> {
                try {
                    out.add(Files.readString(p, StandardCharsets.UTF_8));
                } catch (IOException ignored) {
                    // skip unreadable
                }
            });
            return out;
        } catch (IOException e) {
            return List.of();
        }
    }

    public static List<String> orFallback(String relativePath, List<String> fallback) {
        List<String> loaded = lines(relativePath);
        return loaded.isEmpty() ? fallback : loaded;
    }
}
