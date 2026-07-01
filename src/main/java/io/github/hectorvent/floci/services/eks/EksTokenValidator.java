package io.github.hectorvent.floci.services.eks;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.s3.PreSignedUrlGenerator;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

/**
 * Validates {@code k8s-aws-v1.*} bearer tokens for the EKS token webhook.
 * Under IAM enforcement, verifies SigV4 on an embedded presigned STS {@code GetCallerIdentity} URL.
 */
@ApplicationScoped
public class EksTokenValidator {

    static final String EKS_TOKEN_PREFIX = "k8s-aws-v1.";

    private final EmulatorConfig config;
    private final IamService iamService;
    private final PreSignedUrlGenerator presignGenerator;

    @Inject
    public EksTokenValidator(EmulatorConfig config,
                             IamService iamService,
                             PreSignedUrlGenerator presignGenerator) {
        this.config = config;
        this.iamService = iamService;
        this.presignGenerator = presignGenerator;
    }

    public boolean accepts(String token) {
        if (token == null || !token.startsWith(EKS_TOKEN_PREFIX)) {
            return false;
        }
        if (!config.services().iam().enforcementEnabled()) {
            return true;
        }
        return validatePresignedGetCallerIdentity(token.substring(EKS_TOKEN_PREFIX.length()));
    }

    private boolean validatePresignedGetCallerIdentity(String base64UrlPayload) {
        if (base64UrlPayload == null || base64UrlPayload.isBlank()) {
            return false;
        }
        String urlString;
        try {
            urlString = new String(Base64.getUrlDecoder().decode(base64UrlPayload), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (!isPresignedStsGetCallerIdentityShape(urlString)) {
            return false;
        }

        URI uri;
        try {
            uri = URI.create(urlString);
        } catch (IllegalArgumentException e) {
            return false;
        }

        String hostHeader = hostHeader(uri);
        if (hostHeader == null || hostHeader.isBlank()) {
            return false;
        }

        String rawPath = uri.getRawPath();
        if (rawPath == null || rawPath.isEmpty()) {
            rawPath = "/";
        }
        String rawQuery = uri.getRawQuery();
        if (rawQuery == null || rawQuery.isBlank()) {
            return false;
        }

        String algorithm = SigV4RequestValidator.queryParam(rawQuery, "X-Amz-Algorithm");
        if ("AWS4-ECDSA-P256-SHA256".equals(algorithm)) {
            return false;
        }
        if (!"AWS4-HMAC-SHA256".equals(algorithm)) {
            return false;
        }

        String amzDate = SigV4RequestValidator.queryParam(rawQuery, "X-Amz-Date");
        String expiresStr = SigV4RequestValidator.queryParam(rawQuery, "X-Amz-Expires");
        if (amzDate == null || expiresStr == null) {
            return false;
        }
        int expiresSeconds;
        try {
            expiresSeconds = Integer.parseInt(expiresStr);
        } catch (NumberFormatException e) {
            return false;
        }
        if (presignGenerator.isExpired(amzDate, expiresSeconds)) {
            return false;
        }

        String credential = SigV4RequestValidator.queryParam(rawQuery, "X-Amz-Credential");
        String accessKeyId = SigV4RequestValidator.parseAccessKeyIdFromCredential(credential);
        Optional<String> secret = resolveSecret(accessKeyId);
        if (secret.isEmpty()) {
            return false;
        }

        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                "GET", rawPath, rawQuery, hostHeader, secret.get());
        return result == SigV4RequestValidator.Result.VALID;
    }

    static boolean isPresignedStsGetCallerIdentityShape(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }
        String lower = urlString.toLowerCase(Locale.ROOT);
        if (!lower.contains("getcalleridentity")) {
            return false;
        }
        if (!urlString.contains("X-Amz-Signature=")) {
            return false;
        }
        if (!urlString.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256")) {
            return false;
        }
        return lower.contains("sts") || lower.contains("localhost") || lower.contains("127.0.0.1");
    }

    private Optional<String> resolveSecret(String accessKeyId) {
        if (accessKeyId == null) {
            return Optional.empty();
        }
        Optional<String> rootSecret = config.auth().rootAccessKeyId()
                .filter(accessKeyId::equals)
                .flatMap(ignored -> config.auth().resolveRootSecretAccessKey());
        if (rootSecret.isPresent()) {
            return rootSecret;
        }
        return iamService.findSecretKey(accessKeyId);
    }

    private static String hostHeader(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            return null;
        }
        if (uri.getPort() != -1) {
            return host + ":" + uri.getPort();
        }
        return host;
    }
}
