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

    public static boolean isAwsInspectionPath(String normalizedPath) {
        if (normalizedPath == null || normalizedPath.isEmpty()) {
            return false;
        }
        String normalized = normalizedPath.startsWith("/") ? normalizedPath : "/" + normalizedPath;
        return normalized.startsWith("/_aws/") || "/_aws".equals(normalized);
    }

    public static boolean isPresignedUrlRequest(ContainerRequestContext ctx) {
        return ctx.getUriInfo().getQueryParameters().containsKey("X-Amz-Algorithm");
    }

    /**
     * S3 presigned POST uploads use multipart form bodies validated in {@code S3Controller}.
     */
    public static boolean isPresignedPostRequest(ContainerRequestContext ctx) {
        if (!"POST".equalsIgnoreCase(ctx.getMethod())) {
            return false;
        }
        String contentType = ctx.getHeaderString("Content-Type");
        return contentType != null && contentType.toLowerCase().startsWith("multipart/form-data");
    }

    /**
     * Cognito hosted-UI OAuth routes ({@code /oauth2/token}, {@code /oauth2/userInfo}).
     * AWS authenticates these with app-client {@code client_secret_basic} or Bearer JWT,
     * not SigV4. They are excluded from {@link IamEnforcementFilter} policy evaluation.
     */
    public static boolean isCognitoOAuthPath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        String normalized = normalizePath(path);
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        return isCognitoOAuthTokenPath(normalized) || isCognitoOAuthUserInfoPath(normalized);
    }

    public static boolean isCognitoOAuthTokenPath(String path) {
        return "/cognito-idp/oauth2/token".equals(normalizeLeadingSlash(path));
    }

    public static boolean isCognitoOAuthUserInfoPath(String path) {
        return "/cognito-idp/oauth2/userInfo".equals(normalizeLeadingSlash(path));
    }

    private static String normalizeLeadingSlash(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        String normalized = normalizePath(path);
        return normalized.startsWith("/") ? normalized : "/" + normalized;
    }

    public static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        return path.startsWith("/") ? path.substring(1) : path;
    }
}
