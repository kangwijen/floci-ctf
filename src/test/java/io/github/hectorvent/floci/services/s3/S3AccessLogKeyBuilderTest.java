package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.services.s3.model.LoggingConfiguration;
import io.github.hectorvent.floci.services.s3.model.PartitionedPrefix;
import io.github.hectorvent.floci.services.s3.model.TargetObjectKeyFormat;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertTrue;

class S3AccessLogKeyBuilderTest {

    private static final Instant FIXED = Instant.parse("2026-06-09T12:30:45Z");

    @Test
    void simplePrefixUsesAwsTimestampAndUniqueSuffix() {
        LoggingConfiguration config = new LoggingConfiguration("logs-bucket", "prefix/");
        String key = S3AccessLogKeyBuilder.buildObjectKey(
                config, "000000000000", "us-east-1", "source-bucket", FIXED, FIXED);
        assertTrue(Pattern.compile("prefix/2026-06-09-12-30-45-[0-9a-f]{16}").matcher(key).matches(),
                "unexpected key: " + key);
    }

    @Test
    void partitionedPrefixEventTimeUsesDayPathAndZeroedFileTime() {
        LoggingConfiguration config = new LoggingConfiguration("logs-bucket", "logs/");
        config.setTargetObjectKeyFormat(TargetObjectKeyFormat.partitionedPrefix(new PartitionedPrefix("EventTime")));
        String key = S3AccessLogKeyBuilder.buildObjectKey(
                config, "123456789012", "us-west-2", "src", FIXED, FIXED);
        assertTrue(key.startsWith("logs/123456789012/us-west-2/src/2026/06/09/2026-06-09-00-00-00-"),
                "unexpected key: " + key);
    }

    @Test
    void partitionedPrefixDeliveryTimeUsesFullTimestamp() {
        LoggingConfiguration config = new LoggingConfiguration("logs-bucket", "");
        config.setTargetObjectKeyFormat(
                TargetObjectKeyFormat.partitionedPrefix(new PartitionedPrefix("DeliveryTime")));
        String key = S3AccessLogKeyBuilder.buildObjectKey(
                config, "123456789012", "us-west-2", "src", FIXED, FIXED);
        assertTrue(key.contains("/2026/06/09/2026-06-09-12-30-45-"), "unexpected key: " + key);
    }
}
