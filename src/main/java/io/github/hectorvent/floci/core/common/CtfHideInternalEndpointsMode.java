package io.github.hectorvent.floci.core.common;

/**
 * Parsed value of {@code floci.ctf.hide-internal-endpoints} / {@code FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS}.
 */
public enum CtfHideInternalEndpointsMode {

    /** Internal endpoints are reachable (set {@code FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS=false}). */
    OFF,

    /** Hide {@code /_floci/*}, {@code /_localstack/*}, {@code /_aws/*}, and related operator routes. */
    PREFIXED,

    /** Also hide {@code /health}. */
    ALL;

    public static CtfHideInternalEndpointsMode parse(String raw) {
        if (raw == null || raw.isBlank() || "false".equalsIgnoreCase(raw.trim())) {
            return OFF;
        }
        return switch (raw.trim().toLowerCase()) {
            case "true" -> PREFIXED;
            case "all" -> ALL;
            default -> throw new IllegalArgumentException(
                    "Invalid floci.ctf.hide-internal-endpoints: " + raw
                            + " (expected false, true, or all)");
        };
    }

    public boolean hidesAnything() {
        return this != OFF;
    }

    public boolean isPathHidden(String path) {
        if (!hidesAnything()) {
            return false;
        }
        String normalized = SecurityBypassPaths.normalizePath(path);
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        boolean prefixed = SecurityBypassPaths.isPrefixedInternalPath(normalized)
                || SecurityBypassPaths.isAwsInspectionPath(normalized);
        return switch (this) {
            case OFF -> false;
            case PREFIXED -> prefixed;
            case ALL -> prefixed || "/health".equals(normalized);
        };
    }
}
