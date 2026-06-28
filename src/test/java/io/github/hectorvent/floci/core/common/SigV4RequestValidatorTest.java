package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.s3.PreSignedUrlGenerator;
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
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigV4RequestValidatorTest {

    private static final DateTimeFormatter DATETIME_FMT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @Test
    void validate_acceptsSignedIamQueryPost() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.now();
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
        Instant now = Instant.now();
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
        Instant now = Instant.now();
        String host = "127.0.0.1:4566";
        String path = "/";
        String body = "{\"Name\":\"/app/test/parameter\"}";
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
        Instant now = Instant.now();
        String host = "127.0.0.1:4566";
        String path = "/";
        String body = "{\"Name\":\"/app/test/parameter\"}";
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
        byte[] tamperedPayload = "{\"Name\":\"/app/other\"}".getBytes(StandardCharsets.UTF_8);

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
    void validate_rejectsExpiredRequest() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant expired = Instant.now().minusSeconds(16 * 60);
        String host = "localhost:4566";

        SignedRequest signed = signHeaderAuth(
                "GET",
                "/",
                "",
                host,
                accessKeyId,
                secretKey,
                "us-east-1",
                "sts",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                expired);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("X-Amz-Date", signed.amzDate());
        headers.putSingle("X-Amz-Content-Sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "GET",
                "/",
                "",
                headers,
                signed.authorization(),
                secretKey,
                new byte[0]);

        assertEquals(SigV4RequestValidator.Result.EXPIRED, result);
    }

    @Test
    void validate_acceptsRequestWithinSkewWindow() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant withinSkew = Instant.now().minusSeconds(14 * 60);
        String host = "localhost:4566";

        SignedRequest signed = signHeaderAuth(
                "GET",
                "/",
                "",
                host,
                accessKeyId,
                secretKey,
                "us-east-1",
                "sts",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                withinSkew);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("X-Amz-Date", signed.amzDate());
        headers.putSingle("X-Amz-Content-Sha256",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "GET",
                "/",
                "",
                headers,
                signed.authorization(),
                secretKey,
                new byte[0]);

        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validate_acceptsUnsignedPayloadWhenSignedInHeaders() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.now();
        String host = "localhost:4566";
        String path = "/test-bucket/object.txt";
        String unsignedPayload = "UNSIGNED-PAYLOAD";

        SignedRequest signed = signHeaderAuth(
                "PUT",
                path,
                "",
                host,
                accessKeyId,
                secretKey,
                "us-east-1",
                "s3",
                unsignedPayload,
                now);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("X-Amz-Date", signed.amzDate());
        headers.putSingle("X-Amz-Content-Sha256", unsignedPayload);

        byte[] tamperedBody = "different-body-than-signed".getBytes(StandardCharsets.UTF_8);

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "PUT",
                path,
                "",
                headers,
                signed.authorization(),
                secretKey,
                tamperedBody);

        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validate_acceptsQueryProtocolGet() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        Instant now = Instant.now();
        String host = "localhost:4566";
        String query = "Action=ListUsers&Version=2010-05-08";

        SignedRequest signed = signQueryAuth(
                "/",
                query,
                host,
                accessKeyId,
                secretKey,
                "us-east-1",
                "iam",
                now);

        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.putSingle("Host", host);
        headers.putSingle("X-Amz-Date", signed.amzDate());

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "GET",
                "/",
                query + "&X-Amz-Signature=" + signed.signature(),
                headers,
                signed.authorization(),
                secretKey,
                new byte[0]);

        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void canonicalQueryString_excludesSignatureCaseInsensitively() {
        String query = "Action=ListUsers&x-amz-signature=abc123&Version=2010-05-08";
        String canonical = SigV4RequestValidator.canonicalQueryString(query);
        assertFalse(canonical.toLowerCase(Locale.ROOT).contains("signature"));
        assertTrue(canonical.contains("Action=ListUsers"));
        assertTrue(canonical.contains("Version=2010-05-08"));
    }

    @Test
    void canonicalQueryString_sortsParams() {
        String query = "Version=2010-05-08&Action=ListUsers";
        assertEquals("Action=ListUsers&Version=2010-05-08",
                SigV4RequestValidator.canonicalQueryString(query));
    }

    @Test
    void canonicalUri_encodesPlusInSegment() {
        assertEquals("/bucket/my%2Bkey", SigV4RequestValidator.canonicalUri("/bucket/my+key"));
    }

    @Test
    void validatePresignedUrl_matchesAwsDocumentationExample() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String dateStamp = "20130524";
        String region = "us-east-1";
        String service = "s3";
        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;
        String host = "examplebucket.s3.amazonaws.com";
        String path = "/test.txt";
        String signedHeaders = "host";

        String rawQueryWithoutSignature = PreSignedUrlGenerator.buildPresignQueryWithoutSignature(
                credentialValue, amzDate, 86400, signedHeaders);
        String signature = SigV4RequestValidator.computePresignedSignature(
                "GET",
                path,
                rawQueryWithoutSignature,
                host,
                secretKey,
                amzDate,
                signedHeaders,
                region,
                service,
                dateStamp,
                credentialScope);

        assertEquals("aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404", signature);

        String rawQuery = rawQueryWithoutSignature + "&X-Amz-Signature=" + signature;
        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                "GET", path, rawQuery, host, secretKey);
        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validatePresignedPostPolicy_acceptsValidSignature() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String dateStamp = "20130524";
        String credential = accessKeyId + "/" + dateStamp + "/us-east-1/s3/aws4_request";
        String policyJson = "{\"expiration\":\"2013-08-07T12:00:00.000Z\",\"conditions\":[]}";
        String policyBase64 = Base64.getEncoder().encodeToString(policyJson.getBytes(StandardCharsets.UTF_8));
        String signature = SigV4RequestValidator.computePresignedPostSignature(
                policyBase64, credential, secretKey);

        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedPostPolicy(
                policyBase64,
                "AWS4-HMAC-SHA256",
                credential,
                amzDate,
                signature,
                secretKey);

        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validatePresignedPostPolicy_rejectsTamperedSignature() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String credential = accessKeyId + "/20130524/us-east-1/s3/aws4_request";
        String policyBase64 = Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8));

        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedPostPolicy(
                policyBase64,
                "AWS4-HMAC-SHA256",
                credential,
                amzDate,
                "deadbeef",
                secretKey);

        assertEquals(SigV4RequestValidator.Result.INVALID_SIGNATURE, result);
    }

    @Test
    void validatePresignedUrl_acceptsSseQueryParamsInSignedHeaders() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String dateStamp = "20130524";
        String region = "us-east-1";
        String service = "s3";
        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;
        String host = "examplebucket.s3.amazonaws.com";
        String path = "/encrypted-object.txt";
        String kmsKeyId = "arn:aws:kms:us-east-1:000000000000:key/12345678-1234-1234-1234-123456789012";
        String encryptionContext = Base64.getEncoder().encodeToString(
                "{\"department\":\"finance\"}".getBytes(StandardCharsets.UTF_8));
        String signedHeaders = "host;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id;"
                + "x-amz-server-side-encryption-context";

        Map<String, String> params = new LinkedHashMap<>();
        params.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        params.put("X-Amz-Credential", credentialValue);
        params.put("X-Amz-Date", amzDate);
        params.put("X-Amz-Expires", "86400");
        params.put("X-Amz-SignedHeaders", signedHeaders);
        params.put("X-Amz-Server-Side-Encryption", "aws:kms");
        params.put("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", kmsKeyId);
        params.put("X-Amz-Server-Side-Encryption-Context", encryptionContext);
        String rawQueryWithoutSignature = params.entrySet().stream()
                .map(e -> SigV4RequestValidator.awsUriEncode(e.getKey(), true)
                        + "="
                        + SigV4RequestValidator.awsUriEncode(e.getValue(), true))
                .collect(Collectors.joining("&"));

        String signature = SigV4RequestValidator.computePresignedSignature(
                "PUT",
                path,
                rawQueryWithoutSignature,
                host,
                secretKey,
                amzDate,
                signedHeaders,
                region,
                service,
                dateStamp,
                credentialScope);

        String rawQuery = rawQueryWithoutSignature + "&X-Amz-Signature=" + signature;
        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                "PUT", path, rawQuery, host, secretKey);
        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validatePresignedUrl_acceptsSignedHeadersFromRequestWhenNotInQuery() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String dateStamp = "20130524";
        String region = "us-east-1";
        String service = "s3";
        String credentialScope = dateStamp + "/" + region + "/" + service + "/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;
        String host = "examplebucket.s3.amazonaws.com";
        String path = "/encrypted-object.txt";
        String kmsKeyId = "arn:aws:kms:us-east-1:000000000000:key/12345678-1234-1234-1234-123456789012";
        String signedHeaders = "host;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id";

        Map<String, String> params = new LinkedHashMap<>();
        params.put("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        params.put("X-Amz-Credential", credentialValue);
        params.put("X-Amz-Date", amzDate);
        params.put("X-Amz-Expires", "86400");
        params.put("X-Amz-SignedHeaders", signedHeaders);
        String rawQueryWithoutSignature = params.entrySet().stream()
                .map(e -> SigV4RequestValidator.awsUriEncode(e.getKey(), true)
                        + "="
                        + SigV4RequestValidator.awsUriEncode(e.getValue(), true))
                .collect(Collectors.joining("&"));

        Map<String, String> requestHeaders = Map.of(
                "x-amz-server-side-encryption", "aws:kms",
                "x-amz-server-side-encryption-aws-kms-key-id", kmsKeyId);

        String signature = SigV4RequestValidator.computePresignedSignature(
                "PUT",
                path,
                rawQueryWithoutSignature,
                host,
                secretKey,
                amzDate,
                signedHeaders,
                region,
                service,
                dateStamp,
                credentialScope,
                requestHeaders);

        String rawQuery = rawQueryWithoutSignature + "&X-Amz-Signature=" + signature;
        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                "PUT", path, rawQuery, host, secretKey, requestHeaders);
        assertEquals(SigV4RequestValidator.Result.VALID, result);
    }

    @Test
    void validatePresignedUrl_rejectsSigV4aAlgorithm() {
        String rawQuery = "X-Amz-Algorithm=AWS4-ECDSA-P256-SHA256"
                + "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
                + "&X-Amz-Date=20130524T000000Z"
                + "&X-Amz-Expires=86400"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=abc123";

        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                "GET", "/object.txt", rawQuery, "examplebucket.s3.amazonaws.com", "secret");
        assertEquals(SigV4RequestValidator.Result.INVALID_AUTHORIZATION, result);
    }

    @Test
    void validatePresignedUrl_rejectsTamperedSignature() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String credentialValue = accessKeyId + "/20130524/us-east-1/s3/aws4_request";
        String rawQuery = PreSignedUrlGenerator.buildPresignQueryWithoutSignature(
                credentialValue, amzDate, 86400, "host")
                + "&X-Amz-Signature=deadbeef";

        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedUrl(
                "GET", "/test.txt", rawQuery, "examplebucket.s3.amazonaws.com", secretKey);
        assertEquals(SigV4RequestValidator.Result.INVALID_SIGNATURE, result);
    }

    @Test
    void validatePresignedUrl_usesUnsignedPayloadNotEmptyHash() throws Exception {
        String accessKeyId = "AKIAIOSFODNN7EXAMPLE";
        String secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        String amzDate = "20130524T000000Z";
        String credentialValue = accessKeyId + "/20130524/us-east-1/s3/aws4_request";
        String rawQueryWithoutSignature = PreSignedUrlGenerator.buildPresignQueryWithoutSignature(
                credentialValue, amzDate, 86400, "host");
        String host = "examplebucket.s3.amazonaws.com";
        String path = "/test.txt";

        String signature = SigV4RequestValidator.computePresignedSignature(
                "GET",
                path,
                rawQueryWithoutSignature,
                host,
                secretKey,
                amzDate,
                "host",
                "us-east-1",
                "s3",
                "20130524",
                "20130524/us-east-1/s3/aws4_request");

        String canonicalRequest = "GET\n"
                + path + "\n"
                + SigV4RequestValidator.canonicalQueryString(rawQueryWithoutSignature) + "\n"
                + "host:" + host + "\n"
                + "\n"
                + "host\n"
                + SigV4RequestValidator.UNSIGNED_PAYLOAD;

        String stringToSign = "AWS4-HMAC-SHA256\n"
                + amzDate + "\n"
                + "20130524/us-east-1/s3/aws4_request\n"
                + sha256Hex(canonicalRequest.getBytes(StandardCharsets.UTF_8));

        byte[] signingKey = deriveSigningKey(secretKey, "20130524", "us-east-1", "s3");
        String expectedFromCanonical = hexEncode(hmacSha256(signingKey, stringToSign));
        assertEquals(expectedFromCanonical, signature);
    }

    @Test
    void filter_skipsInternalPaths() {
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("health"));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("_floci/health"));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("_localstack/init"));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/health"));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("s3/my-bucket"));
    }

    @Test
    void internalPathsHiddenWhenCtfHideModeActive() {
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath(
                "_floci/health", CtfHideInternalEndpointsMode.PREFIXED));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath(
                "/health", CtfHideInternalEndpointsMode.ALL));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath(
                "/health", CtfHideInternalEndpointsMode.PREFIXED));
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

    private static SignedRequest signQueryAuth(
            String path,
            String query,
            String host,
            String accessKeyId,
            String secretKey,
            String region,
            String service,
            Instant timestamp
    ) throws Exception {
        String date = DateTimeFormatter.BASIC_ISO_DATE.withZone(ZoneOffset.UTC).format(timestamp);
        String amzDate = DATETIME_FMT.format(timestamp);
        String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
        String credential = accessKeyId + "/" + credentialScope;
        String signedHeaders = "host;x-amz-date";

        Map<String, String> headerValues = new LinkedHashMap<>();
        headerValues.put("host", host);
        headerValues.put("x-amz-date", amzDate);

        String canonicalHeaders = Arrays.stream(signedHeaders.split(";"))
                .sorted()
                .map(name -> name + ":" + trimHeaderValue(headerValues.get(name)))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("") + "\n";

        String payloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        String canonicalRequest = "GET\n"
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
        return new SignedRequest(authorization, amzDate, signature);
    }

    private record SignedRequest(String authorization, String amzDate, String signature) {
        SignedRequest(String authorization, String amzDate) {
            this(authorization, amzDate, null);
        }
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
