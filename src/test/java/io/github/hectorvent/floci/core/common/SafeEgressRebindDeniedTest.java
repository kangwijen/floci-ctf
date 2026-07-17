package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DNS rebind TOCTOU: validate sees a public A record, a later lookup returns private.
 * Pin-connect must use the validated address and must not re-resolve on connect.
 */
@Tag("security-regression")
class SafeEgressRebindDeniedTest {

    @Test
    void pinConnectUsesValidatedAddressAndDoesNotReResolve() throws Exception {
        AtomicInteger lookups = new AtomicInteger();
        HostResolver rebinding = host -> {
            assertEquals("rebind.example", host);
            if (lookups.incrementAndGet() == 1) {
                return new InetAddress[] {InetAddress.getByName("8.8.8.8")};
            }
            return new InetAddress[] {InetAddress.getByName("127.0.0.1")};
        };
        OutboundUrlGuard guard = new OutboundUrlGuard(true, List.of(), false, rebinding);

        PinnedEndpoint pinned = guard.pinHttpUrl("https://rebind.example/jwks.json");

        assertEquals("8.8.8.8", pinned.pinnedAddress().getHostAddress());
        assertEquals("rebind.example", pinned.hostname());
        assertEquals("8.8.8.8", pinned.connectUri().getHost());
        assertEquals("/jwks.json", pinned.connectUri().getPath());
        assertEquals(1, lookups.get(), "pin-connect must resolve DNS only once");
    }

    @Test
    void pinConnectDeniesWhenResolutionRebindsToPrivate() throws Exception {
        AtomicInteger lookups = new AtomicInteger();
        HostResolver rebinding = host -> {
            if (lookups.incrementAndGet() == 1) {
                return new InetAddress[] {InetAddress.getByName("8.8.8.8")};
            }
            return new InetAddress[] {InetAddress.getByName("127.0.0.1")};
        };
        OutboundUrlGuard guard = new OutboundUrlGuard(true, List.of(), false, rebinding);

        guard.pinHttpUrl("https://rebind.example/a");
        AwsException denied = assertThrows(AwsException.class,
                () -> guard.pinHttpUrl("https://rebind.example/b"));
        assertTrue(denied.getMessage().contains("non-public")
                || denied.getMessage().contains("not permitted"), denied.getMessage());
    }
}
