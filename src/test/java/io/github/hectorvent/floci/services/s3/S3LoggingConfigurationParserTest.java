package io.github.hectorvent.floci.services.s3;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class S3LoggingConfigurationParserTest {

    @Test
    void parseSimplePrefixAndTargetGrants() {
        String xml = """
                <BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <LoggingEnabled>
                        <TargetBucket>log-bucket</TargetBucket>
                        <TargetPrefix>logs/</TargetPrefix>
                        <TargetGrant>
                            <Grantee><ID>79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be</ID></Grantee>
                            <Permission>WRITE</Permission>
                        </TargetGrant>
                        <TargetObjectKeyFormat>
                            <SimplePrefix/>
                        </TargetObjectKeyFormat>
                    </LoggingEnabled>
                </BucketLoggingStatus>
                """;

        var config = S3LoggingConfigurationParser.parse(xml);
        assertNotNull(config);
        assertEquals("log-bucket", config.getTargetBucket());
        assertEquals("logs/", config.getTargetPrefix());
        assertEquals(1, config.getTargetGrants().size());
        assertEquals("WRITE", config.getTargetGrants().getFirst().getPermission());
        assertTrue(config.getTargetObjectKeyFormat().isSimplePrefix());
    }

    @Test
    void parsePartitionedPrefixDeliveryTime() {
        String xml = """
                <BucketLoggingStatus>
                    <LoggingEnabled>
                        <TargetBucket>log-bucket</TargetBucket>
                        <TargetPrefix>p/</TargetPrefix>
                        <TargetObjectKeyFormat>
                            <PartitionedPrefix>
                                <PartitionDateSource>DeliveryTime</PartitionDateSource>
                            </PartitionedPrefix>
                        </TargetObjectKeyFormat>
                    </LoggingEnabled>
                </BucketLoggingStatus>
                """;
        var config = S3LoggingConfigurationParser.parse(xml);
        assertNotNull(config);
        assertTrue(config.getTargetObjectKeyFormat().getPartitionedPrefix().isDeliveryTime());
    }
}
