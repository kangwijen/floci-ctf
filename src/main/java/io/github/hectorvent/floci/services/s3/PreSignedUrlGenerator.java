package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@ApplicationScoped
public class PreSignedUrlGenerator {

    private static final DateTimeFormatter AMZ_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private final String secret;
    private final String accessKeyId;
    private final int defaultExpiry;
    private final boolean validateSignatures;
    private final String defaultRegion;

    @Inject
    public PreSignedUrlGenerator(EmulatorConfig config) {
        this(
                config.auth().resolveRootSecretAccessKey()
                        .orElseThrow(() -> new IllegalStateException(
                                "floci.auth.root-secret-access-key (FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY) "
                                        + "is required to sign S3 presigned URLs")),
                config.auth().rootAccessKeyId()
                        .orElseThrow(() -> new IllegalStateException(
                                "floci.auth.root-access-key-id (FLOCI_AUTH_ROOT_ACCESS_KEY_ID) "
                                        + "is required to sign S3 presigned URLs")),
                config.services().s3().defaultPresignExpirySeconds(),
                config.auth().validateSignatures(),
                config.defaultRegion());
    }

    /** Package-private constructor for testing. */
    PreSignedUrlGenerator(String secret, String accessKeyId, int defaultExpiry) {
        this(secret, accessKeyId, defaultExpiry, false, "us-east-1");
    }

    PreSignedUrlGenerator(String secret, String accessKeyId, int defaultExpiry, boolean validateSignatures) {
        this(secret, accessKeyId, defaultExpiry, validateSignatures, "us-east-1");
    }

    PreSignedUrlGenerator(String secret,
                          String accessKeyId,
                          int defaultExpiry,
                          boolean validateSignatures,
                          String defaultRegion) {
        this.secret = secret;
        this.accessKeyId = accessKeyId;
        this.defaultExpiry = defaultExpiry;
        this.validateSignatures = validateSignatures;
        this.defaultRegion = defaultRegion;
    }

    public boolean shouldValidateSignatures() {
        return validateSignatures;
    }

    public String generatePresignedUrl(String baseUrl, String bucket, String key,
                                         String method, int expiresSeconds) {
        int expiry = expiresSeconds > 0 ? expiresSeconds : defaultExpiry;
        Instant now = Instant.now();
        String amzDate = AMZ_DATE_FORMAT.format(now);
        String dateStamp = amzDate.substring(0, 8);
        String credentialScope = dateStamp + "/" + defaultRegion + "/s3/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;
        String signedHeaders = "host";

        URI base = URI.create(baseUrl);
        String host = base.getHost();
        if (base.getPort() > 0) {
            host = host + ":" + base.getPort();
        }

        String rawPath = "/" + bucket + "/" + key;
        String rawQueryWithoutSignature = buildPresignQueryWithoutSignature(
                credentialValue, amzDate, expiry, signedHeaders);

        try {
            String signature = SigV4RequestValidator.computePresignedSignature(
                    method,
                    rawPath,
                    rawQueryWithoutSignature,
                    host,
                    secret,
                    amzDate,
                    signedHeaders,
                    defaultRegion,
                    "s3",
                    dateStamp,
                    credentialScope);

            return baseUrl + rawPath + "?" + rawQueryWithoutSignature + "&X-Amz-Signature=" + signature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to compute presigned URL signature", e);
        }
    }

    /**
     * Parses {@code X-Amz-Date} (SigV4 {@code yyyyMMdd'T'HHmmss'Z'} form).
     * Returns empty when the value is missing or not a valid timestamp.
     */
    public Optional<Instant> parseAmzDate(String amzDate) {
        if (amzDate == null || amzDate.isBlank()) {
            return Optional.empty();
        }
        try {
            return Optional.of(Instant.from(AMZ_DATE_FORMAT.parse(amzDate)));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public boolean isExpired(Instant signedAt, int expiresSeconds) {
        return Instant.now().isAfter(signedAt.plusSeconds(expiresSeconds));
    }

    public Instant expirationTime(Instant signedAt, int expiresSeconds) {
        return signedAt.plusSeconds(expiresSeconds);
    }

    public boolean isExpired(String amzDate, int expiresSeconds) {
        return parseAmzDate(amzDate)
                .map(signedAt -> isExpired(signedAt, expiresSeconds))
                .orElse(true);
    }

    public boolean verifySignature(String method, String bucket, String key,
                                     String amzDate, int expiresSeconds, String signature,
                                     String host) {
        String dateStamp = amzDate.substring(0, 8);
        String credentialScope = dateStamp + "/" + defaultRegion + "/s3/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;
        String rawPath = "/" + bucket + "/" + key;
        String rawQuery = buildPresignQueryWithoutSignature(credentialValue, amzDate, expiresSeconds, "host")
                + "&X-Amz-Signature=" + signature;

        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                method, rawPath, rawQuery, host, secret);
        return result == SigV4RequestValidator.Result.VALID;
    }

    public static String buildPresignQueryWithoutSignature(String credentialValue,
                                                    String amzDate,
                                                    int expiresSeconds,
                                                    String signedHeaders) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        params.put("X-Amz-Credential", credentialValue);
        params.put("X-Amz-Date", amzDate);
        params.put("X-Amz-Expires", Integer.toString(expiresSeconds));
        params.put("X-Amz-SignedHeaders", signedHeaders);
        return params.entrySet().stream()
                .map(e -> SigV4RequestValidator.awsUriEncode(e.getKey(), true)
                        + "="
                        + SigV4RequestValidator.awsUriEncode(e.getValue(), true))
                .collect(Collectors.joining("&"));
    }
}
