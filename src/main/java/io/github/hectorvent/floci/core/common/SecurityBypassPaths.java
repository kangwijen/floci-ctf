package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;

import java.nio.charset.StandardCharsets;

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
     * Requires {@code policy}/{@code Policy} or {@code x-amz-algorithm} form field markers.
     */
    public static boolean isPresignedPostRequest(ContainerRequestContext ctx) {
        if (!isMultipartBucketPostRequest(ctx)) {
            return false;
        }
        byte[] body = RequestBodyBuffer.peek(ctx);
        if (body == null) {
            body = RequestBodyBuffer.buffer(ctx);
        }
        return multipartBodyContainsField(body, "policy", "Policy", "x-amz-algorithm");
    }

    /**
     * Unauthenticated S3 bucket POST with {@code multipart/form-data} (not {@code ?delete}).
     */
    public static boolean isMultipartBucketPostRequest(ContainerRequestContext ctx) {
        if (!"POST".equalsIgnoreCase(ctx.getMethod())) {
            return false;
        }
        String contentType = ctx.getHeaderString("Content-Type");
        if (contentType == null || !contentType.toLowerCase().startsWith("multipart/form-data")) {
            return false;
        }
        return isS3BucketPostPath(ctx);
    }

    private static boolean isS3BucketPostPath(ContainerRequestContext ctx) {
        if (ctx.getUriInfo().getQueryParameters().containsKey("delete")) {
            return false;
        }
        String path = ctx.getUriInfo().getPath();
        if (path == null || path.isEmpty()) {
            return false;
        }
        if (isInternalHealthOrInfoPath(path)) {
            return false;
        }
        String normalized = path.startsWith("/") ? path.substring(1) : path;
        return !normalized.isEmpty() && !normalized.contains("/");
    }

    private static boolean multipartBodyContainsField(byte[] body, String... fieldNames) {
        if (body == null || body.length == 0) {
            return false;
        }
        String raw = new String(body, StandardCharsets.ISO_8859_1);
        for (String name : fieldNames) {
            if (raw.contains("name=\"" + name + "\"") || raw.contains("name='" + name + "'")) {
                return true;
            }
        }
        return false;
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
