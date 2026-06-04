package io.github.hectorvent.floci.services.eks;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;

/**
 * Validates {@code k8s-aws-v1.*} bearer tokens for the EKS token webhook.
 * Under IAM enforcement, requires a plausible presigned STS {@code GetCallerIdentity} URL
 * instead of accepting any string with the prefix.
 */
final class EksTokenAuthenticator {

    static final String EKS_TOKEN_PREFIX = "k8s-aws-v1.";

    private EksTokenAuthenticator() {
    }

    static boolean accepts(String token, boolean iamEnforcementEnabled) {
        if (token == null || !token.startsWith(EKS_TOKEN_PREFIX)) {
            return false;
        }
        if (!iamEnforcementEnabled) {
            return true;
        }
        return isPlausiblePresignedStsGetCallerIdentity(token.substring(EKS_TOKEN_PREFIX.length()));
    }

    static boolean isPlausiblePresignedStsGetCallerIdentity(String base64UrlPayload) {
        if (base64UrlPayload == null || base64UrlPayload.isBlank()) {
            return false;
        }
        try {
            String url = new String(Base64.getUrlDecoder().decode(base64UrlPayload), StandardCharsets.UTF_8);
            String lower = url.toLowerCase(Locale.ROOT);
            return lower.contains("getcalleridentity")
                    && url.contains("X-Amz-Signature=")
                    && url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256")
                    && lower.contains("sts");
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
