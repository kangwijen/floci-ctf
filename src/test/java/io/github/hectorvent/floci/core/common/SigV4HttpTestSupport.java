package io.github.hectorvent.floci.core.common;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Signs HTTP requests for integration tests with {@code floci.auth.validate-signatures=true}.
 */
public final class SigV4HttpTestSupport {

    private static final DateTimeFormatter DATETIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    private SigV4HttpTestSupport() {}

    private static final String EMPTY_PAYLOAD_HASH =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    public record SignedHeaders(String authorization, String amzDate, String contentSha256) {}

    public record SignedRestHeaders(
            String authorization,
            String amzDate,
            String contentSha256,
            String securityToken
    ) {}

    public static SignedHeaders signFormPost(
            String host,
            int port,
            String accessKeyId,
            String secretKey,
            String region,
            String service,
            String formBody,
            Instant timestamp
    ) throws Exception {
        String path = "/";
        String payloadHash = sha256Hex(formBody.getBytes(StandardCharsets.UTF_8));
        String date = DateTimeFormatter.BASIC_ISO_DATE.withZone(ZoneOffset.UTC).format(timestamp);
        String amzDate = DATETIME_FMT.format(timestamp);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date";
        String contentType = "application/x-www-form-urlencoded; charset=ISO-8859-1";
        String hostHeader = host + ":" + port;

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("content-type", contentType);
        headerValues.put("host", hostHeader);
        headerValues.put("x-amz-content-sha256", payloadHash);
        headerValues.put("x-amz-date", amzDate);

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .sorted()
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String canonicalRequest = "POST\n"
                + SigV4RequestValidator.canonicalUri(path) + "\n"
                + SigV4RequestValidator.canonicalQueryString("") + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
        String signature = hexEncode(hmacSha256(signingKey, stringToSign));
        String authorization = "AWS4-HMAC-SHA256 Credential=" + credential
                + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature;
        return new SignedHeaders(authorization, amzDate, payloadHash);
    }

    public static SignedRestHeaders signRestPost(
            String host,
            int port,
            String path,
            byte[] body,
            String accessKeyId,
            String secretKey,
            String region,
            String service,
            Instant timestamp
    ) throws Exception {
        return signRestPost(host, port, path, body, accessKeyId, secretKey, null, region, service, timestamp);
    }

    public static SignedRestHeaders signRestPost(
            String host,
            int port,
            String path,
            byte[] body,
            String accessKeyId,
            String secretKey,
            String sessionToken,
            String region,
            String service,
            Instant timestamp
    ) throws Exception {
        String payloadHash = sha256Hex(body);
        String amzDate = DATETIME_FMT.format(timestamp);
        String date = amzDate.substring(0, 8);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String hostHeader = host + ":" + port;
        String contentType = "application/json; charset=UTF-8";

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("content-type", contentType);
        headerValues.put("host", hostHeader);
        headerValues.put("x-amz-content-sha256", payloadHash);
        headerValues.put("x-amz-date", amzDate);
        if (sessionToken != null && !sessionToken.isBlank()) {
            headerValues.put("x-amz-security-token", sessionToken);
        }

        String signedHeaders = String.join(";",
                headerValues.keySet().stream().sorted().toList());

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String canonicalRequest = "POST\n"
                + SigV4RequestValidator.canonicalUri(path) + "\n"
                + SigV4RequestValidator.canonicalQueryString("") + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
        String signature = hexEncode(hmacSha256(signingKey, stringToSign));
        String authorization = "AWS4-HMAC-SHA256 Credential=" + credential
                + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature;
        return new SignedRestHeaders(authorization, amzDate, payloadHash, sessionToken);
    }

    public static SignedRestHeaders signRestGet(
            String host,
            int port,
            String path,
            String accessKeyId,
            String secretKey,
            String sessionToken,
            String region,
            String service,
            Instant timestamp
    ) throws Exception {
        String payloadHash = EMPTY_PAYLOAD_HASH;
        String amzDate = DATETIME_FMT.format(timestamp);
        String date = amzDate.substring(0, 8);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String hostHeader = host + ":" + port;

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("host", hostHeader);
        headerValues.put("x-amz-content-sha256", payloadHash);
        headerValues.put("x-amz-date", amzDate);
        if (sessionToken != null && !sessionToken.isBlank()) {
            headerValues.put("x-amz-security-token", sessionToken);
        }

        String signedHeaders = String.join(";",
                headerValues.keySet().stream().sorted().toList());

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String canonicalRequest = "GET\n"
                + SigV4RequestValidator.canonicalUri(path) + "\n"
                + SigV4RequestValidator.canonicalQueryString("") + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
        String signature = hexEncode(hmacSha256(signingKey, stringToSign));
        String authorization = "AWS4-HMAC-SHA256 Credential=" + credential
                + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature;
        return new SignedRestHeaders(authorization, amzDate, payloadHash, sessionToken);
    }

    public static SignedRestHeaders signRestPut(
            String host,
            int port,
            String path,
            byte[] body,
            String accessKeyId,
            String secretKey,
            String sessionToken,
            String region,
            String service,
            Instant timestamp
    ) throws Exception {
        String payloadHash = sha256Hex(body);
        String amzDate = DATETIME_FMT.format(timestamp);
        String date = amzDate.substring(0, 8);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String hostHeader = host + ":" + port;

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("host", hostHeader);
        headerValues.put("x-amz-content-sha256", payloadHash);
        headerValues.put("x-amz-date", amzDate);
        if (sessionToken != null && !sessionToken.isBlank()) {
            headerValues.put("x-amz-security-token", sessionToken);
        }

        String signedHeaders = String.join(";",
                headerValues.keySet().stream().sorted().toList());

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String canonicalRequest = "PUT\n"
                + SigV4RequestValidator.canonicalUri(path) + "\n"
                + SigV4RequestValidator.canonicalQueryString("") + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
        String signature = hexEncode(hmacSha256(signingKey, stringToSign));
        String authorization = "AWS4-HMAC-SHA256 Credential=" + credential
                + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature;
        return new SignedRestHeaders(authorization, amzDate, payloadHash, sessionToken);
    }

    private static String trimHeaderValue(String value) {
        return value.trim().replaceAll("\\s+", " ");
    }

    private static byte[] deriveSigningKey(String secretKey, String date, String region,
                                           String service) throws Exception {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(StandardCharsets.UTF_8);
        byte[] kDate = hmacSha256(kSecret, date);
        byte[] kRegion = hmacSha256(kDate, region);
        byte[] kService = hmacSha256(kRegion, service);
        return hmacSha256(kService, "aws4_request");
    }

    private static byte[] hmacSha256(byte[] key, String data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hexEncode(digest.digest(data));
    }

    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format(Locale.ROOT, "%02x", b));
        }
        return sb.toString();
    }
}
