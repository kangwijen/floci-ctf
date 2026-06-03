package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;

/**
 * Shared path and request classification for auth-related filters.
 */
public final class SecurityBypassPaths {

    private SecurityBypassPaths() {
    }

    public static boolean isInternalHealthOrInfoPath(String path) {
        return isInternalHealthOrInfoPath(path, CtfHideInternalEndpointsMode.OFF);
    }

    public static boolean isInternalHealthOrInfoPath(String path, CtfHideInternalEndpointsMode hideMode) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String normalized = normalizePath(path);
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        if (hideMode != null && hideMode.isPathHidden(normalized)) {
            return false;
        }
        return "/health".equals(normalized) || isPrefixedInternalPath(normalized);
    }

    public static boolean isPrefixedInternalPath(String normalizedPath) {
        if (normalizedPath == null || normalizedPath.isEmpty()) {
            return false;
        }
        String normalized = normalizedPath.startsWith("/") ? normalizedPath : "/" + normalizedPath;
        return normalized.startsWith("/_floci/")
                || "/_floci".equals(normalized)
                || normalized.startsWith("/_localstack/")
                || "/_localstack".equals(normalized);
    }

    public static boolean isPresignedUrlRequest(ContainerRequestContext ctx) {
        return ctx.getUriInfo().getQueryParameters().containsKey("X-Amz-Algorithm");
    }

    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        return path.startsWith("/") ? path.substring(1) : path;
    }
}
