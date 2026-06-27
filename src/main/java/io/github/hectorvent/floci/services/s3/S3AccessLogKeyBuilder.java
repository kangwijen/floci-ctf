package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.services.s3.model.LoggingConfiguration;
import io.github.hectorvent.floci.services.s3.model.PartitionedPrefix;
import io.github.hectorvent.floci.services.s3.model.TargetObjectKeyFormat;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.UUID;

/**
 * Builds S3 server access log object keys per
 * <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html">AWS server access logging</a>.
 */
final class S3AccessLogKeyBuilder {

    private static final DateTimeFormatter SIMPLE_SUFFIX = DateTimeFormatter
            .ofPattern("yyyy-MM-dd-HH-mm-ss", Locale.ROOT)
            .withZone(ZoneOffset.UTC);

    private S3AccessLogKeyBuilder() {
    }

    static String buildObjectKey(LoggingConfiguration logging,
                                 String sourceAccountId,
                                 String sourceRegion,
                                 String sourceBucket,
                                 Instant eventTime,
                                 Instant deliveryTime) {
        String prefix = logging.getTargetPrefix() != null ? logging.getTargetPrefix() : "";
        TargetObjectKeyFormat format = logging.getTargetObjectKeyFormat();
        String unique = uniqueSuffix();
        if (format != null && format.getPartitionedPrefix() != null) {
            return buildPartitionedKey(prefix, format.getPartitionedPrefix(),
                    sourceAccountId, sourceRegion, sourceBucket, eventTime, deliveryTime, unique);
        }
        Instant timestamp = deliveryTime != null ? deliveryTime : eventTime;
        return prefix + SIMPLE_SUFFIX.format(timestamp) + "-" + unique;
    }

    private static String buildPartitionedKey(String prefix,
                                              PartitionedPrefix partitioned,
                                              String sourceAccountId,
                                              String sourceRegion,
                                              String sourceBucket,
                                              Instant eventTime,
                                              Instant deliveryTime,
                                              String unique) {
        Instant partitionInstant = partitioned.isDeliveryTime()
                ? (deliveryTime != null ? deliveryTime : Instant.now())
                : (eventTime != null ? eventTime : Instant.now());
        Instant fileInstant = partitioned.isDeliveryTime()
                ? partitionInstant
                : eventTime != null ? eventTime : partitionInstant;

        String account = sanitizePathSegment(sourceAccountId);
        String region = sanitizePathSegment(sourceRegion);
        String bucket = sanitizePathSegment(sourceBucket);

        DateTimeFormatter dayPath = DateTimeFormatter.ofPattern("yyyy/MM/dd", Locale.ROOT)
                .withZone(ZoneOffset.UTC);
        String day = dayPath.format(partitionInstant);

        DateTimeFormatter fileTime = DateTimeFormatter.ofPattern("yyyy-MM-dd-HH-mm-ss", Locale.ROOT)
                .withZone(ZoneOffset.UTC);
        String fileStamp;
        if (partitioned.isDeliveryTime()) {
            fileStamp = fileTime.format(fileInstant);
        } else {
            DateTimeFormatter dayOnly = DateTimeFormatter.ofPattern("yyyy-MM-dd", Locale.ROOT)
                    .withZone(ZoneOffset.UTC);
            fileStamp = dayOnly.format(partitionInstant) + "-00-00-00";
        }

        return prefix + account + "/" + region + "/" + bucket + "/"
                + day + "/" + fileStamp + "-" + unique;
    }

    private static String uniqueSuffix() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    private static String sanitizePathSegment(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim();
    }
}
