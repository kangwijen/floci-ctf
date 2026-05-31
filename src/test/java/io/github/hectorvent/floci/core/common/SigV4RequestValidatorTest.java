package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigV4RequestValidatorTest {

    private static final DateTimeFormatter DATETIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @Test
    void validate_acceptsSignedIamQueryPost() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.parse("2026-05-31T12:00:00Z");
        String host = "localhost:4566";
        String path = "/";
        String body = "Action=ListUsers&Version=2010-05-08";
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        String payloadHash = sha256Hex(payload);

        SignedRequest signed = signHeaderAuth(
                "POST",
                path,
                "",
                host,
                accessKeyId,
                secretKey,
                "us-east-1",
                "iam",
                payloadHash,
                now);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("X-Amz-Date", signed.amzDate());
        headers.putSingle("X-Amz-Content-Sha256", payloadHash);

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "POST",
                path,
                "",
                headers,
                signed.authorization(),
                secretKey,
                payload);

        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validate_rejectsWrongSecret() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.parse("2026-05-31T12:00:00Z");
        String host = "localhost:4566";

        SignedRequest signed = signHeaderAuth(
                "GET",
                "/000000000000/test-queue",
                "",
                host,
                accessKeyId,
                secretKey,
                "us-east-1",
                "sqs",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                now);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("X-Amz-Date", signed.amzDate());
        headers.putSingle("X-Amz-Content-Sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "GET",
                "/000000000000/test-queue",
                "",
                headers,
                signed.authorization(),
                "wrong-secret",
                new byte[0]);

        assertEquals(SigV4RequestValidator.Result.INVALID_SIGNATURE, result);
    }

    /**
     * AWS CLI v2 standard SigV4 for JSON-protocol services (e.g. SSM, STS) computes
     * the payload hash and includes it only as the last line of the canonical request.
     * It does NOT send x-amz-content-sha256 as a header or include it in SignedHeaders.
     * Floci must compute the hash from the buffered body in this case.
     */
    @Test
    void validate_acceptsStandardV4WithoutContentSha256Header() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.parse("2026-05-31T12:00:00Z");
        String host = "127.0.0.1:4566";
        String path = "/";
        String body = "{\"Name\":\"/nimbus/challenge/escalation\"}";
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        String payloadHash = sha256Hex(payload);

        SignedRequest signed = signHeaderAuthNoContentSha256(
                "POST",
                path,
                "",
                host,
                "application/x-amz-json-1.1",
                accessKeyId,
                secretKey,
                "us-east-1",
                "ssm",
                payloadHash,
                now);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("Content-Type", "application/x-amz-json-1.1");
        headers.putSingle("X-Amz-Date", signed.amzDate());
        // x-amz-content-sha256 intentionally absent from headers and SignedHeaders

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "POST",
                path,
                "",
                headers,
                signed.authorization(),
                secretKey,
                payload);

        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validate_rejectsWrongBodyWhenNoContentSha256Header() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.parse("2026-05-31T12:00:00Z");
        String host = "127.0.0.1:4566";
        String path = "/";
        String body = "{\"Name\":\"/nimbus/challenge/escalation\"}";
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        String payloadHash = sha256Hex(payload);

        SignedRequest signed = signHeaderAuthNoContentSha256(
                "POST",
                path,
                "",
                host,
                "application/x-amz-json-1.1",
                accessKeyId,
                secretKey,
                "us-east-1",
                "ssm",
                payloadHash,
                now);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("Content-Type", "application/x-amz-json-1.1");
        headers.putSingle("X-Amz-Date", signed.amzDate());

        // Tampered body: different content than what was signed
        byte[] tamperedPayload = "{\"Name\":\"/nimbus/flag\"}".getBytes(StandardCharsets.UTF_8);

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "POST",
                path,
                "",
                headers,
                signed.authorization(),
                secretKey,
                tamperedPayload);

        assertEquals(SigV4RequestValidator.Result.INVALID_SIGNATURE, result);
    }

    @Test
    void canonicalUri_encodesSegments() {
        assertEquals("/000000000000/my%20queue", SigV4RequestValidator.canonicalUri("/000000000000/my queue"));
    }

    @Test
    void filter_skipsInternalPaths() {
        assertTrue(SigV4ValidationFilter.isInternalPath("health"));
        assertTrue(SigV4ValidationFilter.isInternalPath("_floci/health"));
        assertTrue(SigV4ValidationFilter.isInternalPath("_localstack/init"));
    }

    private static SignedRequest signHeaderAuth(
            String method,
            String path,
            String query,
            String host,
            String accessKeyId,
            String secretKey,
            String region,
            String service,
            String payloadHash,
            Instant timestamp
    ) throws Exception {
        String date = DateTimeFormatter.BASIC_ISO_DATE.withZone(ZoneOffset.UTC).format(timestamp);
        String amzDate = DATETIME_FMT.format(timestamp);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String signedHeaders = "host;x-amz-content-sha256;x-amz-date";

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("host", host);
        headerValues.put("x-amz-content-sha256", payloadHash);
        headerValues.put("x-amz-date", amzDate);

        String canonicalHeaders = signedHeaders.split(";").length == 0 ? "" :
                java.util.Arrays.stream(signedHeaders.split(";"))
                        .sorted()
                        .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                        .reduce((a, b) -> a + "\n" + b)
                        .orElse("") + "\n";

        String canonicalRequest = method.toUpperCase(Locale.ROOT) + "\n"
                + SigV4RequestValidator.canonicalUri(path) + "\n"
                + SigV4RequestValidator.canonicalQueryString(query) + "\n"
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
        return new SignedRequest(authorization, amzDate);
    }

    /**
     * Signs a request WITHOUT x-amz-content-sha256 in SignedHeaders, matching the
     * behaviour of AWS CLI v2 and standard boto3 for non-S3 services.
     */
    private static SignedRequest signHeaderAuthNoContentSha256(
            String method,
            String path,
            String query,
            String host,
            String contentType,
            String accessKeyId,
            String secretKey,
            String region,
            String service,
            String payloadHash,
            Instant timestamp
    ) throws Exception {
        String date = DateTimeFormatter.BASIC_ISO_DATE.withZone(ZoneOffset.UTC).format(timestamp);
        String amzDate = DATETIME_FMT.format(timestamp);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String signedHeaders = "content-type;host;x-amz-date";

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("content-type", contentType);
        headerValues.put("host", host);
        headerValues.put("x-amz-date", amzDate);

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .sorted()
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String canonicalRequest = method.toUpperCase(Locale.ROOT) + "\n"
                + SigV4RequestValidator.canonicalUri(path) + "\n"
                + SigV4RequestValidator.canonicalQueryString(query) + "\n"
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
        return new SignedRequest(authorization, amzDate);
    }

    private record SignedRequest(String authorization, String amzDate) {
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

    private static String sha256Hex(byte[] input) throws Exception {
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
