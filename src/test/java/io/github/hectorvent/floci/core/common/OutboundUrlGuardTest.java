package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("security-regression")
class OutboundUrlGuardTest {

    private final OutboundUrlGuard guard = new OutboundUrlGuard(true, List.of(), false);

    @Test
    void blocksNonPublicAddresses() throws Exception {
        assertTrue(guard.isBlockedAddress(InetAddress.getByName("127.0.0.1")));
        assertTrue(guard.isBlockedAddress(InetAddress.getByName("10.0.0.1")));
        assertTrue(guard.isBlockedAddress(InetAddress.getByName("169.254.169.254")));
        assertTrue(guard.isBlockedAddress(InetAddress.getByName("fc00::1")));
    }

    @Test
    void permitsPublicAddresses() throws Exception {
        assertFalse(guard.isBlockedAddress(InetAddress.getByName("8.8.8.8")));
        assertDoesNotThrow(() -> guard.validateHttpUrl("https://8.8.8.8/resource"));
    }

    @Test
    void rejectsPrivateAndMetadataUrls() {
        assertThrows(AwsException.class, () -> guard.validateHttpUrl("http://127.0.0.1:8080"));
        assertThrows(AwsException.class, () -> guard.validateHttpUrl("http://169.254.169.254/latest/meta-data"));
        assertThrows(AwsException.class, () -> guard.validateHttpUrl("http://metadata.google.internal"));
    }

    @Test
    void requiresHttpOrHttps() {
        assertThrows(IllegalArgumentException.class, () -> guard.validateHttpUrl("ftp://example.com"));
    }

    @Test
    void allowsUnresolvedPublicHostnames() {
        assertDoesNotThrow(() -> guard.validateHttpUrl("https://other.example.com/path"));
    }

    @Test
    void allowsApiGatewayPathTemplates() {
        assertDoesNotThrow(() -> guard.validateHttpUrl("http://example.com/{proxy}"));
    }

    @Test
    void permitsLocalhostWhenBlockingDisabled() {
        OutboundUrlGuard open = new OutboundUrlGuard(false, List.of(), false);
        assertDoesNotThrow(() -> open.validateHttpUrl("http://localhost:4566/2015-03-31/functions/fn/invocations"));
    }
}
