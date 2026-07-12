package io.github.hectorvent.floci.fuzz.oracle;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Minimized finding recorded by unit or operator fuzz campaigns.
 */
public final class Finding {

    public enum Kind {
        SECURITY,
        CRASH,
        HANG
    }

    private final Kind kind;
    private final String target;
    private final String summary;
    private final String seed;
    private final Map<String, String> details;
    private final Instant recordedAt;

    public Finding(Kind kind, String target, String summary, String seed, Map<String, String> details) {
        this.kind = Objects.requireNonNull(kind, "kind");
        this.target = Objects.requireNonNull(target, "target");
        this.summary = Objects.requireNonNull(summary, "summary");
        this.seed = seed == null ? "" : seed;
        this.details = details == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(details));
        this.recordedAt = Instant.now();
    }

    public Kind kind() {
        return kind;
    }

    public String target() {
        return target;
    }

    public String summary() {
        return summary;
    }

    public String seed() {
        return seed;
    }

    public Map<String, String> details() {
        return details;
    }

    public Instant recordedAt() {
        return recordedAt;
    }
}
