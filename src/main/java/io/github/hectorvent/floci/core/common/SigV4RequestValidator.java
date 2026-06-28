package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.core.MultivaluedMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates inbound AWS SigV4 {@code Authorization} header signatures for REST and
 * Query-protocol HTTP requests.
 */
public final class SigV4RequestValidator {

    private static final Pattern AUTH_HEADER_PATTERN = Pattern.compile(
            "^AWS4-HMAC-SHA256 Credential=([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]+)$");
    private static final DateTimeFormatter DATETIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final String EMPTY_PAYLOAD_HASH =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /** S3 presigned URL payload placeholder per AWS SigV4 query-string auth. */
    public static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    private static final long MAX_SKEW_SECONDS = 15 * 60;

    private SigV4RequestValidator() {
    }

    public enum Result {
        VALID,
        INVALID_SIGNATURE,
        INVALID_AUTHORIZATION,
        EXPIRED
    }

    /**
     * Validates an inbound SigV4 Authorization header.
     *
     * @param body the raw request body bytes, used to compute the payload hash when
     *             the client did not include {@code x-amz-content-sha256} as a signed
     *             header (standard AWS SDK v4 behaviour for non-S3 services). Pass an
     *             empty array for bodyless requests (GET, DELETE, etc.).
     */
    public static Result validate(String method,
                                  String rawPath,
                                  String rawQuery,
                                  MultivaluedMap<String, String> headers,
                                  String authorizationHeader,
                                  String secretKey,
                                  byte[] body) {
        try {
            Matcher auth = AUTH_HEADER_PATTERN.matcher(authorizationHeader.trim());
            if (!auth.matches()) {
                return Result.INVALID_AUTHORIZATION;
            }

            String credential = auth.group(1).trim();
            String signedHeadersList = auth.group(2).trim().toLowerCase(Locale.ROOT);
            String providedSignature = auth.group(3).trim();

            String[] credParts = credential.split("/");
            if (credParts.length < 5) {
                return Result.INVALID_AUTHORIZATION;
            }
            String date = credParts[1];
            String region = credParts[2];
            String service = credParts[3];
            String credentialScope = date + "/" + region + "/" + service + "/aws4_request";

            String amzDate = headerValue(headers, "x-amz-date");
            if (amzDate == null) {
                return Result.INVALID_AUTHORIZATION;
            }
            if (isExpired(amzDate)) {
                return Result.EXPIRED;
            }

            String canonicalRequest = buildCanonicalRequest(
                    method,
                    rawPath,
                    rawQuery,
                    headers,
                    signedHeadersList,
                    body);

            String stringToSign = "AWS4-HMAC-SHA256\n"
                    + amzDate + "\n"
                    + credentialScope + "\n"
                    + sha256Hex(canonicalRequest);

            byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
            String expectedSignature = hexEncode(hmacSha256(signingKey, stringToSign));

            if (MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    providedSignature.getBytes(StandardCharsets.UTF_8))) {
                return Result.VALID;
            }
            return Result.INVALID_SIGNATURE;
        } catch (Exception e) {
            return Result.INVALID_SIGNATURE;
        }
    }

    /**
     * Validates an inbound S3 presigned URL (SigV4 query-string authentication).
     *
     * @param rawQuery the raw query string including {@code X-Amz-Signature}
     * @param hostHeader value of the HTTP {@code Host} header used in the signature
     */
    public static Result validatePresignedUrl(String method,
                                              String rawPath,
                                              String rawQuery,
                                              String hostHeader,
                                              String secretKey) {
        return validatePresignedUrl(method, rawPath, rawQuery, hostHeader, secretKey, null);
    }

    /**
     * Validates an inbound S3 presigned URL (SigV4 query-string authentication).
     *
     * @param requestHeaders optional inbound headers; signed {@code x-amz-*} values fall back here
     *                       when absent from the query string
     */
    public static Result validatePresignedUrl(String method,
                                              String rawPath,
                                              String rawQuery,
                                              String hostHeader,
                                              String secretKey,
                                              Map<String, String> requestHeaders) {
        try {
            if (rawQuery == null || rawQuery.isBlank()) {
                return Result.INVALID_AUTHORIZATION;
            }
            if (hostHeader == null || hostHeader.isBlank()) {
                return Result.INVALID_AUTHORIZATION;
            }

            String algorithm = queryParam(rawQuery, "X-Amz-Algorithm");
            if ("AWS4-ECDSA-P256-SHA256".equals(algorithm)) {
                return Result.INVALID_AUTHORIZATION;
            }
            if (!"AWS4-HMAC-SHA256".equals(algorithm)) {
                return Result.INVALID_AUTHORIZATION;
            }

            String credential = queryParam(rawQuery, "X-Amz-Credential");
            String amzDate = queryParam(rawQuery, "X-Amz-Date");
            String signedHeadersList = queryParam(rawQuery, "X-Amz-SignedHeaders");
            String providedSignature = queryParam(rawQuery, "X-Amz-Signature");

            if (credential == null || amzDate == null || signedHeadersList == null || providedSignature == null) {
                return Result.INVALID_AUTHORIZATION;
            }

            String[] credParts = credential.split("/");
            if (credParts.length < 5) {
                return Result.INVALID_AUTHORIZATION;
            }
            String date = credParts[1];
            String region = credParts[2];
            String service = credParts[3];
            String credentialScope = date + "/" + region + "/" + service + "/aws4_request";

            String expectedSignature = computePresignedSignature(
                    method,
                    rawPath,
                    rawQuery,
                    hostHeader,
                    secretKey,
                    amzDate,
                    signedHeadersList,
                    region,
                    service,
                    date,
                    credentialScope,
                    requestHeaders);

            if (MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    providedSignature.getBytes(StandardCharsets.UTF_8))) {
                return Result.VALID;
            }
            return Result.INVALID_SIGNATURE;
        } catch (Exception e) {
            return Result.INVALID_SIGNATURE;
        }
    }

    /**
     * Validates an S3 presigned POST policy signature (SigV4).
     *
     * <p>StringToSign is {@code hex(SHA256(policyBase64))} where {@code policyBase64} is the
     * base64 policy string from the form field. Signature is
     * {@code hex(HMAC-SHA256(signingKey, StringToSign))} with the signing key derived from
     * {@code credential} date, region, and service.
     */
    public static Result validatePresignedPostPolicy(String policyBase64,
                                                     String algorithm,
                                                     String credential,
                                                     String amzDate,
                                                     String providedSignature,
                                                     String secretKey) {
        try {
            if (policyBase64 == null || policyBase64.isBlank()) {
                return Result.INVALID_AUTHORIZATION;
            }
            if (!"AWS4-HMAC-SHA256".equals(algorithm)) {
                return Result.INVALID_AUTHORIZATION;
            }
            if (credential == null || credential.isBlank()
                    || amzDate == null || amzDate.isBlank()
                    || providedSignature == null || providedSignature.isBlank()) {
                return Result.INVALID_AUTHORIZATION;
            }

            String[] credParts = credential.split("/");
            if (credParts.length < 5) {
                return Result.INVALID_AUTHORIZATION;
            }
            String date = credParts[1];
            String region = credParts[2];
            String service = credParts[3];

            String expectedSignature = computePresignedPostSignature(
                    policyBase64, credential, secretKey);

            if (MessageDigest.isEqual(
                    expectedSignature.getBytes(StandardCharsets.UTF_8),
                    providedSignature.getBytes(StandardCharsets.UTF_8))) {
                return Result.VALID;
            }
            return Result.INVALID_SIGNATURE;
        } catch (Exception e) {
            return Result.INVALID_SIGNATURE;
        }
    }

    /**
     * Computes the SigV4 signature for an S3 presigned POST policy.
     */
    public static String computePresignedPostSignature(String policyBase64,
                                                       String credential,
                                                       String secretKey) throws Exception {
        String[] credParts = credential.split("/");
        if (credParts.length < 5) {
            throw new IllegalArgumentException("Invalid X-Amz-Credential");
        }
        String date = credParts[1];
        String region = credParts[2];
        String service = credParts[3];
        String stringToSign = sha256Hex(policyBase64);
        byte[] signingKey = deriveSigningKey(secretKey, date, region, service);
        return hexEncode(hmacSha256(signingKey, stringToSign));
    }

    /**
     * Computes the SigV4 signature for an S3 presigned URL (query params except
     * {@code X-Amz-Signature} must already be present in {@code rawQuery}).
     */
    public static String computePresignedSignature(String method,
                                                   String rawPath,
                                                   String rawQuery,
                                                   String hostHeader,
                                                   String secretKey,
                                                   String amzDate,
                                                   String signedHeadersList,
                                                   String region,
                                                   String service,
                                                   String dateStamp,
                                                   String credentialScope) throws Exception {
        return computePresignedSignature(
                method,
                rawPath,
                rawQuery,
                hostHeader,
                secretKey,
                amzDate,
                signedHeadersList,
                region,
                service,
                dateStamp,
                credentialScope,
                null);
    }

    public static String computePresignedSignature(String method,
                                                   String rawPath,
                                                   String rawQuery,
                                                   String hostHeader,
                                                   String secretKey,
                                                   String amzDate,
                                                   String signedHeadersList,
                                                   String region,
                                                   String service,
                                                   String dateStamp,
                                                   String credentialScope,
                                                   Map<String, String> requestHeaders) throws Exception {
        String canonicalRequest = buildPresignedCanonicalRequest(
                method, rawPath, rawQuery, hostHeader, signedHeadersList, requestHeaders);

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest);

        byte[] signingKey = deriveSigningKey(secretKey, dateStamp, region, service);
        return hexEncode(hmacSha256(signingKey, stringToSign));
    }

    /**
     * Parses the access key ID from {@code X-Amz-Credential} ({@code accessKey/date/region/service/aws4_request}).
     */
    public static String parseAccessKeyIdFromCredential(String credential) {
        if (credential == null || credential.isBlank()) {
            return null;
        }
        int slash = credential.indexOf('/');
        return slash < 0 ? credential : credential.substring(0, slash);
    }

    private static String buildPresignedCanonicalRequest(String method,
                                                         String rawPath,
                                                         String rawQuery,
                                                         String hostHeader,
                                                         String signedHeadersList) throws Exception {
        return buildPresignedCanonicalRequest(
                method, rawPath, rawQuery, hostHeader, signedHeadersList, null);
    }

    private static String buildPresignedCanonicalRequest(String method,
                                                         String rawPath,
                                                         String rawQuery,
                                                         String hostHeader,
                                                         String signedHeadersList,
                                                         Map<String, String> requestHeaders) throws Exception {
        String normalizedSignedHeaders = signedHeadersList.toLowerCase(Locale.ROOT);
        String[] signedHeaderNames = normalizedSignedHeaders.split(";");
        List<String> canonicalHeaderLines = new ArrayList<>();
        for (String name : signedHeaderNames) {
            String trimmedName = name.trim();
            if (trimmedName.isEmpty()) {
                continue;
            }
            String value = presignedHeaderValue(trimmedName, hostHeader, rawQuery, requestHeaders);
            if (value == null) {
                throw new IllegalStateException("Missing signed header: " + trimmedName);
            }
            canonicalHeaderLines.add(trimmedName + ":" + trimHeaderValue(value));
        }
        canonicalHeaderLines.sort(Comparator.naturalOrder());
        String canonicalHeaders = String.join("\n", canonicalHeaderLines) + "\n";

        return method.toUpperCase(Locale.ROOT) + "\n"
                + canonicalUri(rawPath) + "\n"
                + canonicalQueryString(rawQuery) + "\n"
                + canonicalHeaders + "\n"
                + normalizedSignedHeaders + "\n"
                + UNSIGNED_PAYLOAD;
    }

    private static String presignedHeaderValue(String headerName,
                                               String hostHeader,
                                               String rawQuery,
                                               Map<String, String> requestHeaders) {
        if ("host".equals(headerName)) {
            return hostHeader;
        }
        if (headerName.startsWith("x-amz-")) {
            String queryName = headerNameToQueryParam(headerName);
            String fromQuery = queryParam(rawQuery, queryName);
            if (fromQuery != null) {
                return fromQuery;
            }
            if (requestHeaders != null) {
                for (Map.Entry<String, String> entry : requestHeaders.entrySet()) {
                    if (entry.getKey() != null
                            && headerName.equals(entry.getKey().toLowerCase(Locale.ROOT))) {
                        return entry.getValue();
                    }
                }
            }
        }
        return null;
    }

    private static String headerNameToQueryParam(String headerName) {
        StringBuilder sb = new StringBuilder("X-Amz-");
        for (int i = 6; i < headerName.length(); i++) {
            char c = headerName.charAt(i);
            if (c == '-') {
                sb.append('-');
            } else {
                sb.append(Character.toUpperCase(c));
            }
        }
        return sb.toString();
    }

    static String queryParam(String rawQuery, String paramName) {
        if (rawQuery == null || paramName == null) {
            return null;
        }
        for (String part : rawQuery.split("&")) {
            if (part.isEmpty()) {
                continue;
            }
            int eq = part.indexOf('=');
            String rawName = eq >= 0 ? part.substring(0, eq) : part;
            String decodedName = urlDecode(rawName);
            if (paramName.equalsIgnoreCase(rawName) || paramName.equalsIgnoreCase(decodedName)) {
                return eq >= 0 ? urlDecode(part.substring(eq + 1)) : "";
            }
        }
        return null;
    }

    private static boolean isSignedHeader(String signedHeadersList, String headerName) {
        for (String name : signedHeadersList.split(";")) {
            if (headerName.equals(name.trim())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isExpired(String amzDate) {
        try {
            Instant requestTime = Instant.from(DATETIME_FMT.parse(amzDate));
            Instant now = Instant.now();
            return requestTime.isBefore(now.minusSeconds(MAX_SKEW_SECONDS))
                    || requestTime.isAfter(now.plusSeconds(MAX_SKEW_SECONDS));
        } catch (Exception e) {
            return true;
        }
    }

    private static String buildCanonicalRequest(String method,
                                                String rawPath,
                                                String rawQuery,
                                                MultivaluedMap<String, String> headers,
                                                String signedHeadersList,
                                                byte[] body) throws Exception {
        String canonicalUri = canonicalUri(rawPath);
        String canonicalQueryString = canonicalQueryString(rawQuery);
        String[] signedHeaderNames = signedHeadersList.split(";");
        List<String> canonicalHeaderLines = new ArrayList<>();
        for (String name : signedHeaderNames) {
            String value = headerValue(headers, name);
            if (value == null) {
                throw new IllegalStateException("Missing signed header: " + name);
            }
            canonicalHeaderLines.add(name + ":" + trimHeaderValue(value));
        }
        canonicalHeaderLines.sort(Comparator.naturalOrder());
        String canonicalHeaders = String.join("\n", canonicalHeaderLines) + "\n";

        String payloadHash;
        if (isSignedHeader(signedHeadersList, "x-amz-content-sha256")) {
            // Client signed the hash header: read it directly from headers.
            payloadHash = headerValue(headers, "x-amz-content-sha256");
            if (payloadHash == null || payloadHash.isBlank()) {
                payloadHash = EMPTY_PAYLOAD_HASH;
            }
        } else {
            // Standard SigV4 for non-S3 services (e.g. AWS CLI v2 signing SSM/STS):
            // the payload hash is computed from the body and included only in the
            // canonical request, not sent as a header.
            payloadHash = (body != null && body.length > 0)
                    ? sha256HexBytes(body)
                    : EMPTY_PAYLOAD_HASH;
        }

        return method.toUpperCase(Locale.ROOT) + "\n"
                + canonicalUri + "\n"
                + canonicalQueryString + "\n"
                + canonicalHeaders + "\n"
                + signedHeadersList + "\n"
                + payloadHash;
    }

    private static String headerValue(MultivaluedMap<String, String> headers,
                                      String lowercaseName) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey() != null
                    && entry.getKey().toLowerCase(Locale.ROOT).equals(lowercaseName)) {
                List<String> values = entry.getValue();
                if (values == null || values.isEmpty()) {
                    return null;
                }
                return String.join(",", values);
            }
        }
        return null;
    }

    private static String trimHeaderValue(String value) {
        String trimmed = value.trim();
        return trimmed.replaceAll("\\s+", " ");
    }

    static String canonicalUri(String rawPath) {
        if (rawPath == null || rawPath.isEmpty()) {
            return "/";
        }
        if (!rawPath.startsWith("/")) {
            rawPath = "/" + rawPath;
        }
        if ("/".equals(rawPath)) {
            return "/";
        }
        String[] segments = rawPath.split("/", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i < segments.length; i++) {
            sb.append("/").append(awsUriEncode(segments[i], true));
        }
        return sb.length() == 0 ? "/" : sb.toString();
    }

    static String canonicalQueryString(String rawQuery) {
        if (rawQuery == null || rawQuery.isBlank()) {
            return "";
        }
        List<String> pairs = new ArrayList<>();
        for (String part : rawQuery.split("&")) {
            if (part.isEmpty()) {
                continue;
            }
            int eq = part.indexOf('=');
            String rawName = eq >= 0 ? part.substring(0, eq) : part;
            String rawValue = eq >= 0 ? part.substring(eq + 1) : "";
            if (isSignatureQueryParam(rawName)) {
                continue;
            }
            String name = awsUriEncode(urlDecode(rawName), true);
            String value = awsUriEncode(urlDecode(rawValue), true);
            pairs.add(name + "=" + value);
        }
        pairs.sort(Comparator.naturalOrder());
        return String.join("&", pairs);
    }

    private static boolean isSignatureQueryParam(String rawName) {
        if (rawName == null || rawName.isEmpty()) {
            return false;
        }
        String decoded = urlDecode(rawName);
        return "X-Amz-Signature".equalsIgnoreCase(rawName)
                || "X-Amz-Signature".equalsIgnoreCase(decoded);
    }

    private static String urlDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    public static String awsUriEncode(String value, boolean encodeSlash) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~");
        if (!encodeSlash) {
            encoded = encoded.replace("%2F", "/");
        }
        return encoded;
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

    private static String sha256Hex(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hexEncode(digest.digest(input.getBytes(StandardCharsets.UTF_8)));
    }

    private static String sha256HexBytes(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return hexEncode(digest.digest(input));
    }

    private static String hexEncode(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
