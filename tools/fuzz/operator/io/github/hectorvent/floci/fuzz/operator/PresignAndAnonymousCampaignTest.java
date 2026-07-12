package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Unsigned S3 path and anonymous Lambda URL deny campaigns against live CTF Compose.
 *
 * <p>Skipped unless {@code -Pfuzz-operator} and {@code AWS_ENDPOINT_URL} are set.
 */
class PresignAndAnonymousCampaignTest {

    private static final DateTimeFormatter AMZ_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final String REGION = "us-east-1";

    private static Optional<DifferentialHttpOracle> live() {
        if (Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true"))) {
            return Optional.empty();
        }
        return DifferentialHttpOracle.fromEnv();
    }

    @Property(tries = 15)
    void unsignedGetBucketKeyPathDenied(
            @ForAll @AlphaChars @StringLength(min = 3, max = 12) String bucket,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String key) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String path = "/" + bucket.toLowerCase() + "/" + key;
        DifferentialHttpOracle.ProbeResult result = oracle.exchange("GET", path, Map.of(), null);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Presign.unsigned.get",
                    path,
                    "unsigned S3 GET succeeded without presign or public policy",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Property(tries = 10)
    void unsignedPutBucketKeyPathDenied(
            @ForAll @AlphaChars @StringLength(min = 3, max = 12) String bucket,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String key) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String path = "/" + bucket.toLowerCase() + "/" + key;
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "PUT",
                path,
                Map.of("Content-Type", "application/octet-stream"),
                "fuzz-payload");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Presign.unsigned.put",
                    path,
                    "unsigned S3 PUT succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedMultipartPostWithFakePolicyFieldsDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String boundary = "----FlociFuzzBoundary";
        String policyJson = """
                {
                  "expiration": "2030-01-01T00:00:00.000Z",
                  "conditions": [
                    {"bucket": "fuzz-bucket"},
                    {"key": "fuzz/object"}
                  ]
                }
                """;
        String policyBase64 = Base64.getEncoder().encodeToString(
                policyJson.getBytes(StandardCharsets.UTF_8));
        String body = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"key\"\r\n\r\n"
                + "fuzz/object\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"policy\"\r\n\r\n"
                + policyBase64 + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-algorithm\"\r\n\r\n"
                + "AWS4-HMAC-SHA256\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-credential\"\r\n\r\n"
                + "AKIAFAKE00/20300101/us-east-1/s3/aws4_request\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-date\"\r\n\r\n"
                + "20300101T000000Z\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n"
                + "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n"
                + "Content-Type: text/plain\r\n\r\n"
                + "hello\r\n"
                + "--" + boundary + "--\r\n";
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/fuzz-bucket",
                Map.of("Content-Type", "multipart/form-data; boundary=" + boundary),
                body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Presign.fake.multipart",
                    "/fuzz-bucket",
                    "multipart POST with fake policy/signature fields succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void tamperedPresignedPostSignatureDeniedWhenPresignCredsPresent() throws Exception {
        Assumptions.assumeTrue(
                ParticipantCredentials.presignFromEnv().isPresent(),
                "Set FUZZ_PRESIGN_ACCESS_KEY_ID and FUZZ_PRESIGN_SECRET_ACCESS_KEY for signed mutation");
        DifferentialHttpOracle oracle = requireOracle();
        ParticipantCredentials creds = ParticipantCredentials.presignFromEnv().orElseThrow();
        String bucket = "fuzz-bucket";
        String key = "fuzz/signed-mutation.txt";
        String policyJson = buildPolicy(bucket, key);
        String policyBase64 = Base64.getEncoder().encodeToString(
                policyJson.getBytes(StandardCharsets.UTF_8));
        Instant now = Instant.now();
        String amzDate = AMZ_DATE_FORMAT.format(now);
        String dateStamp = amzDate.substring(0, 8);
        String credential = creds.accessKeyId() + "/" + dateStamp + "/" + REGION + "/s3/aws4_request";
        String signature = SigV4RequestValidator.computePresignedPostSignature(
                policyBase64, credential, creds.secretAccessKey());
        String tamperedSignature = signature.startsWith("0")
                ? "1" + signature.substring(1)
                : "0" + signature.substring(1);

        String boundary = "----FlociFuzzPresign";
        String body = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"key\"\r\n\r\n"
                + key + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"policy\"\r\n\r\n"
                + policyBase64 + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-algorithm\"\r\n\r\n"
                + "AWS4-HMAC-SHA256\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-credential\"\r\n\r\n"
                + credential + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-date\"\r\n\r\n"
                + amzDate + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"x-amz-signature\"\r\n\r\n"
                + tamperedSignature + "\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n"
                + "Content-Type: text/plain\r\n\r\n"
                + "hello\r\n"
                + "--" + boundary + "--\r\n";
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/" + bucket,
                Map.of("Content-Type", "multipart/form-data; boundary=" + boundary),
                body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Presign.tampered.signature",
                    "/" + bucket,
                    "tampered presigned POST signature succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    private static String buildPolicy(String bucket, String key) {
        String expiration = Instant.now().plusSeconds(3600)
                .atZone(ZoneOffset.UTC)
                .format(DateTimeFormatter.ISO_INSTANT);
        return """
                {
                  "expiration": "%s",
                  "conditions": [
                    {"bucket": "%s"},
                    {"key": "%s"},
                    ["content-length-range", 0, 10485760]
                  ]
                }
                """.formatted(expiration, bucket, key);
    }

    @Test
    void unsignedMultipartPostWithoutPolicyDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String boundary = "----FlociFuzzBoundary";
        String body = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"key\"\r\n\r\n"
                + "fuzz/object\r\n"
                + "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n"
                + "Content-Type: text/plain\r\n\r\n"
                + "hello\r\n"
                + "--" + boundary + "--\r\n";
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/fuzz-bucket",
                Map.of("Content-Type", "multipart/form-data; boundary=" + boundary),
                body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Presign.unsigned.multipart",
                    "/fuzz-bucket",
                    "unsigned multipart POST without policy succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedLambdaUrlWithoutResourcePolicyDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "GET", "/lambda-url/fake-fn", Map.of(), null);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Presign.anonymous.lambdaUrl",
                    "/lambda-url/fake-fn",
                    "unsigned lambda-url invoke succeeded without intentional resource policy",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    private static DifferentialHttpOracle requireOracle() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        Optional<DifferentialHttpOracle> maybe = live();
        Assumptions.assumeTrue(maybe.isPresent(),
                "Set AWS_ENDPOINT_URL for presign/anonymous campaigns");
        return maybe.get();
    }
}
