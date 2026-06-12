package io.github.hectorvent.floci.services.s3;

import java.time.Instant;

public record S3AccessLogContext(
        String sourceBucket,
        String key,
        String operation,
        String requestUri,
        int httpStatus,
        String errorCode,
        long bytesSent,
        Long objectSize,
        long totalTimeMs,
        String remoteIp,
        String requester,
        String requestId,
        String hostId,
        String userAgent,
        String referer,
        String versionId,
        String signatureVersion,
        String authenticationType,
        String hostHeader,
        Instant timestamp) {
}
