package io.github.hectorvent.floci.core.common.port;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.*;

class PortAllocatorTest {

  private static int freeBasePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  /** Finds {@code count} consecutive host-free ports; retries when the suite leaves listeners behind. */
  private static int contiguousFreeRange(int count) throws IOException {
    for (int attempt = 0; attempt < 200; attempt++) {
      int base = freeBasePort();
      if (rangeIsHostFree(base, base + count - 1)) {
        return base;
      }
    }
    throw new IOException("Could not find " + count + " contiguous free ports after 200 attempts");
  }

  private static boolean rangeIsHostFree(int from, int to) {
    for (int port = from; port <= to; port++) {
      if (!PortAllocator.isPortFree(port)) {
        return false;
      }
    }
    return true;
  }

    @Test
    void allocatesSequentiallyFromBase() throws IOException {
        int base = contiguousFreeRange(3);
        PortAllocator allocator = new PortAllocator(base, base + 99);
        assertEquals(base, allocator.allocate());
        assertEquals(base + 1, allocator.allocate());
        assertEquals(base + 2, allocator.allocate());
    }

    @Test
    void concurrentAllocationsAreUnique() throws IOException, InterruptedException {
        int base = contiguousFreeRange(50);
        PortAllocator allocator = new PortAllocator(base, base + 99);
        int threads = 50;
        Set<Integer> ports = ConcurrentHashMap.newKeySet();
        CountDownLatch latch = new CountDownLatch(threads);
        ExecutorService executor = Executors.newFixedThreadPool(threads);

        for (int i = 0; i < threads; i++) {
            executor.submit(() -> {
                ports.add(allocator.allocate());
                latch.countDown();
            });
        }

        latch.await();
        executor.shutdown();
        assertEquals(threads, ports.size(), "All allocated ports must be unique");
    }

    @Test
    void allocateNeverReturnsPortAlreadyHandedOut() throws IOException {
        int base = contiguousFreeRange(10);
        PortAllocator allocator = new PortAllocator(base, base + 9, false);
        Set<Integer> handed = new HashSet<>();
        for (int i = 0; i < 10; i++) {
            assertTrue(handed.add(allocator.allocate()));
        }
        assertThrows(IllegalStateException.class, allocator::allocate);
    }

    @Test
    void releasedPortBecomesAvailableAgain() throws IOException {
        int base = contiguousFreeRange(2);
        PortAllocator allocator = new PortAllocator(base, base + 1, false);
        int first = allocator.allocate();
        allocator.allocate();
        assertThrows(IllegalStateException.class, allocator::allocate);

        allocator.release(first);
        assertEquals(first, allocator.allocate());
    }

    @Test
    void allocateFromRangeSkipsHostBoundPorts() throws IOException {
        int base = contiguousFreeRange(3);
        try (ServerSocket blocker = new ServerSocket(base)) {
            blocker.setReuseAddress(true);
            Set<Integer> inUse = ConcurrentHashMap.newKeySet();
            assertEquals(base + 1, PortAllocator.allocateFromRange(base, base + 2, inUse, false));
        }
    }

    @Test
    void allocateFromRangeFallsBackToEphemeralWhenRangeBusy() throws IOException {
        int base = contiguousFreeRange(1);
        try (ServerSocket blocker = new ServerSocket(base)) {
            blocker.setReuseAddress(true);
            Set<Integer> inUse = ConcurrentHashMap.newKeySet();
            int port = PortAllocator.allocateFromRange(base, base, inUse, true);
            assertNotEquals(base, port);
            assertTrue(inUse.contains(port));
        }
    }

    @Test
    void skipsPortsAlreadyBoundOnHost() throws IOException {
        int base = contiguousFreeRange(3);
        try (ServerSocket blocker = new ServerSocket(base)) {
            blocker.setReuseAddress(true);
            PortAllocator allocator = new PortAllocator(base, base + 2, false);
            assertEquals(base + 1, allocator.allocate());
            assertEquals(base + 2, allocator.allocate());
            assertThrows(IllegalStateException.class, allocator::allocate);
        }
    }

    @Test
    void fallsBackToEphemeralWhenConfiguredRangeIsBusy() throws IOException {
        int base = contiguousFreeRange(1);
        try (ServerSocket blocker = new ServerSocket(base)) {
            blocker.setReuseAddress(true);
            PortAllocator allocator = new PortAllocator(base, base);
            int port = allocator.allocate();
            assertNotEquals(base, port);
            allocator.release(port);
        }
    }
}
