package io.github.hectorvent.floci.services.elasticache.proxy;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

@Tag("security-regression")
class ElastiCacheMemcachedAuthProxyTest {

    @Test
    void readAsciiLineParsesAuthCommand() throws Exception {
        String line = ElastiCacheMemcachedAuthProxy.readAsciiLine(
                new ByteArrayInputStream("auth my-token\r\n".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("auth my-token", line);
    }

    @Test
    void readAsciiLineReturnsNullOnEmptyStream() throws Exception {
        assertNull(ElastiCacheMemcachedAuthProxy.readAsciiLine(new ByteArrayInputStream(new byte[0])));
    }
}
