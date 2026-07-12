package io.github.hectorvent.floci.fuzz.operator;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Signs outbound HTTP requests for live participant differential probes.
 */
public final class ParticipantSigV4Signer {

    private static final DateTimeFormatter DATETIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final String EMPTY_PAYLOAD_HASH =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    private ParticipantSigV4Signer() {
    }

    public static Map<String, String> sign(
            URI endpoint,
            String method,
            String path,
            String body,
            ParticipantCredentials creds,
            String region,
            String service,
            Map<String, String> extraSignedHeaders) throws Exception {
        byte[] bodyBytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        String payloadHash = bodyBytes.length == 0 ? EMPTY_PAYLOAD_HASH : sha256Hex(bodyBytes);
        Instant now = Instant.now();
        String amzDate = DATETIME_FMT.format(now);
        String date = amzDate.substring(0, 8);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = creds.accessKeyId() + "/" + credentialScope;
        String hostHeader = hostHeader(endpoint);

        Map<String, String> headerValues = new LinkedHashMap<>();
        if (extraSignedHeaders != null) {
            for (Map.Entry<String, String> entry : extraSignedHeaders.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    headerValues.put(entry.getKey().toLowerCase(Locale.ROOT), entry.getValue());
                }
            }
        }
        if (!headerValues.containsKey("host")) {
            headerValues.put("host", hostHeader);
        }
        headerValues.put("x-amz-content-sha256", payloadHash);
        headerValues.put("x-amz-date", amzDate);
        if (creds.sessionToken() != null && !creds.sessionToken().isBlank()) {
            headerValues.put("x-amz-security-token", creds.sessionToken());
        }

        String signedHeaders = String.join(";",
                headerValues.keySet().stream().sorted().toList());

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String normalizedPath = path == null || path.isBlank() ? "/" : path;
        String canonicalRequest = method.toUpperCase(Locale.ROOT) + "\n"
                + canonicalUri(normalizedPath) + "\n"
                + canonicalQueryString("") + "\n"
                + canonicalHeaders + "\n"
                + signedHeaders + "\n"
                + payloadHash;

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] signingKey = deriveSigningKey(creds.secretAccessKey(), date, region, service);
        String signature = hexEncode(hmacSha256(signingKey, stringToSign));
        String authorization = "AWS4-HMAC-SHA256 Credential=" + credential
                + ", SignedHeaders=" + signedHeaders
                + ", Signature=" + signature;

        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : headerValues.entrySet()) {
            out.put(canonicalHeaderName(entry.getKey()), entry.getValue());
        }
        out.put("Authorization", authorization);
        return out;
    }

    private static String hostHeader(URI endpoint) {
        int port = endpoint.getPort();
        if (port < 0) {
            port = "https".equalsIgnoreCase(endpoint.getScheme()) ? 443 : 80;
        }
        String host = endpoint.getHost();
        if ((port == 80 && "http".equalsIgnoreCase(endpoint.getScheme()))
                || (port == 443 && "https".equalsIgnoreCase(endpoint.getScheme()))) {
            return host;
        }
        return host + ":" + port;
    }

    private static String canonicalHeaderName(String lowerName) {
        return switch (lowerName) {
            case "content-type" -> "Content-Type";
            case "host" -> "Host";
            case "x-amz-content-sha256" -> "x-amz-content-sha256";
            case "x-amz-date" -> "x-amz-date";
            case "x-amz-security-token" -> "x-amz-security-token";
            case "x-amz-target" -> "X-Amz-Target";
            default -> lowerName;
        };
    }

    private static String trimHeaderValue(String value) {
        return value.trim().replaceAll("\\s+", " ");
    }

    private static String canonicalUri(String rawPath) {
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

    private static String canonicalQueryString(String rawQuery) {
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
            String name = awsUriEncode(urlDecode(rawName), true);
            String value = awsUriEncode(urlDecode(rawValue), true);
            pairs.add(name + "=" + value);
        }
        pairs.sort(Comparator.naturalOrder());
        return String.join("&", pairs);
    }

    private static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private static String awsUriEncode(String value, boolean encodeSlash) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xff);
            if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '_'
                    || c == '-'
                    || c == '~'
                    || c == '.') {
                sb.append(c);
            } else if (c == '/' && !encodeSlash) {
                sb.append(c);
            } else {
                sb.append('%').append(String.format(Locale.ROOT, "%02X", b & 0xff));
            }
        }
        return sb.toString();
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
