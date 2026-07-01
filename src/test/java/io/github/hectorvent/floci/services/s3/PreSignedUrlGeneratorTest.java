package io.github.hectorvent.floci.services.s3;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PreSignedUrlGeneratorTest {

    private static final String SECRET = "test-secret";
    private static final String ACCESS_KEY = "AKIATESTPRESIGN01";

    private final PreSignedUrlGenerator generator =
            new PreSignedUrlGenerator(SECRET, ACCESS_KEY, 3600, true);

    @Test
    void parseAmzDateAcceptsSigV4Timestamp() {
        assertTrue(generator.parseAmzDate("20260205T120000Z").isPresent());
    }

    @Test
    void parseAmzDateRejectsMalformedValue() {
        assertTrue(generator.parseAmzDate("not-a-date").isEmpty());
        assertTrue(generator.parseAmzDate("").isEmpty());
    }

    @Test
    void isExpiredReturnsTrueAfterWindowElapses() {
        Instant signedAt = Instant.now().minus(2, ChronoUnit.HOURS);
        assertTrue(generator.isExpired(signedAt, 60));
    }

    @Test
    void isExpiredReturnsFalseInsideWindow() {
        Instant signedAt = Instant.now().minus(30, ChronoUnit.SECONDS);
        assertFalse(generator.isExpired(signedAt, 3600));
    }

    @Test
    void expirationTimeAddsExpiresSecondsToSignedAt() {
        Instant signedAt = Instant.parse("2020-01-01T00:00:00Z");
        assertEquals(Instant.parse("2020-01-01T00:00:01Z"),
                generator.expirationTime(signedAt, 1));
    }

    @Test
    void verifySignatureMatchesGeneratedUrl() {
        String presignedUrl = generator.generatePresignedUrl(
                "http://localhost:4566", "b", "k.txt", "GET", 300);
        URI uri = URI.create(presignedUrl);
        String host = uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");

        String sigParam = uri.getRawQuery().substring(
                uri.getRawQuery().indexOf("X-Amz-Signature=") + "X-Amz-Signature=".length());
        String dateParam = uri.getRawQuery().substring(
                uri.getRawQuery().indexOf("X-Amz-Date=") + "X-Amz-Date=".length(),
                uri.getRawQuery().indexOf("&X-Amz-Expires="));

        assertTrue(generator.verifySignature("GET", "b", "k.txt", dateParam, 300, sigParam, host));
    }

    @Test
    void verifySignatureRejectsTamperedSignature() {
        assertFalse(generator.verifySignature(
                "GET", "b", "k.txt", "20260205T120000Z", 300, "deadbeef", "localhost:4566"));
    }

    @Test
    void generatePresignedUrlWithSseQueryParamsIncludesSignedParams() {
        String kmsKeyId = "arn:aws:kms:us-east-1:000000000000:key/12345678-1234-1234-1234-123456789012";
        java.util.Map<String, String> sseParams = java.util.Map.of(
                "X-Amz-Server-Side-Encryption", "aws:kms",
                "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", kmsKeyId);

        String presignedUrl = generator.generatePresignedUrl(
                "http://localhost:4566", "b", "k.txt", "PUT", 300, sseParams);
        URI uri = URI.create(presignedUrl);
        String host = uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : "");

        assertTrue(uri.getRawQuery().contains("X-Amz-Server-Side-Encryption=aws%3Akms"));
        assertTrue(uri.getRawQuery().contains("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id="));

        String sigParam = uri.getRawQuery().substring(
                uri.getRawQuery().indexOf("X-Amz-Signature=") + "X-Amz-Signature=".length());
        String dateParam = uri.getRawQuery().substring(
                uri.getRawQuery().indexOf("X-Amz-Date=") + "X-Amz-Date=".length(),
                uri.getRawQuery().indexOf("&X-Amz-Expires="));

        assertTrue(generator.verifySignature("PUT", "b", "k.txt", dateParam, 300, sigParam, host, sseParams));
    }

}
