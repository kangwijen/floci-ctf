package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;

import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Shared path and request classification for auth-related filters.
 */
public final class SecurityBypassPaths {

    public static final String SQS_QUEUE_URL_PROPERTY = "floci.sqs.queueUrl";

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

    /**
     * Federated STS assume-role calls authenticate with a JWT or SAML assertion in the
     * form body, not SigV4. {@link io.github.hectorvent.floci.services.iam.StsQueryHandler}
     * validates trust policies for these operations.
     */
    public static boolean isFederatedStsAssumeRequest(ContainerRequestContext ctx) {
        if (!"POST".equalsIgnoreCase(ctx.getMethod())) {
            return false;
        }
        String action = readUrlEncodedFormField(ctx, "Action");
        if (action == null || action.isBlank()) {
            return false;
        }
        return switch (action) {
            case "AssumeRoleWithWebIdentity" -> hasUrlEncodedFormField(ctx, "WebIdentityToken");
            case "AssumeRoleWithSAML" -> hasUrlEncodedFormField(ctx, "SAMLAssertion");
            default -> false;
        };
    }

    private static boolean hasUrlEncodedFormField(ContainerRequestContext ctx, String fieldName) {
        String value = readUrlEncodedFormField(ctx, fieldName);
        return value != null && !value.isBlank();
    }

    private static String readUrlEncodedFormField(ContainerRequestContext ctx, String fieldName) {
        MediaType mediaType = ctx.getMediaType();
        if (mediaType == null
                || !"application".equalsIgnoreCase(mediaType.getType())
                || !"x-www-form-urlencoded".equalsIgnoreCase(mediaType.getSubtype())) {
            return null;
        }
        byte[] body = RequestBodyBuffer.peek(ctx);
        if (body == null) {
            body = RequestBodyBuffer.buffer(ctx);
        }
        if (body.length == 0) {
            return null;
        }
        Charset charset = resolveFormCharset(mediaType);
        String form = new String(body, charset);
        for (String pair : form.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            if (!fieldName.equals(URLDecoder.decode(key, charset))) {
                continue;
            }
            return eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), charset);
        }
        return null;
    }

    private static Charset resolveFormCharset(MediaType mediaType) {
        String name = mediaType.getParameters().get("charset");
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
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
