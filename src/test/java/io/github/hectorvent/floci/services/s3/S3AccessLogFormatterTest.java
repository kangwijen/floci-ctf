package io.github.hectorvent.floci.services.s3;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertTrue;

class S3AccessLogFormatterTest {

    @Test
    void formatLineIncludesAllTwentySevenAwsFields() {
        S3AccessLogContext ctx = new S3AccessLogContext(
                "source-bucket",
                "object.txt",
                "REST.PUT.OBJECT",
                "PUT /source-bucket/object.txt HTTP/1.1",
                200,
                "-",
                13,
                13L,
                42,
                40,
                "192.0.2.3",
                "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
                "3E57427F3EXAMPLE",
                "hostid==",
                "curl/7.88.1",
                "https://example.com",
                "-",
                "SigV4",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "AuthHeader",
                "localhost:4566",
                "TLSv1.2",
                "-",
                "-",
                "us-east-1",
                Instant.parse("2026-06-09T00:00:38Z"));

        String line = S3AccessLogFormatter.formatLine(ctx, ctx.requester());
        assertTrue(line.contains("REST.PUT.OBJECT"));
        assertTrue(line.contains("\"PUT /source-bucket/object.txt HTTP/1.1\""));
        assertTrue(line.contains("\"curl/7.88.1\""));
        assertTrue(line.contains("ECDHE-RSA-AES128-GCM-SHA256"));
        assertTrue(line.endsWith(" us-east-1"));
        assertTrue(line.contains(" 40 "));
        assertTrue(line.contains(" 42 "));
    }
}
