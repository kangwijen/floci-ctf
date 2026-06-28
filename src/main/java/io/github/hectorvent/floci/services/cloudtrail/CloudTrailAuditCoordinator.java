package io.github.hectorvent.floci.services.cloudtrail;

import jakarta.enterprise.context.ApplicationScoped;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks in-flight HTTP audit recordings so {@code LookupEvents} can wait for
 * concurrent response filters to finish indexing before scanning the store.
 */
@ApplicationScoped
public class CloudTrailAuditCoordinator {

    private static final int QUIET_POLL_ATTEMPTS = 200;
    private static final long QUIET_POLL_SLEEP_MS = 1L;

    private final AtomicInteger inFlightRecordings = new AtomicInteger();

    public void beginRecording() {
        inFlightRecordings.incrementAndGet();
    }

    public void endRecording() {
        inFlightRecordings.decrementAndGet();
    }

    public void awaitQuiet() {
        for (int attempt = 0; attempt < QUIET_POLL_ATTEMPTS; attempt++) {
            if (inFlightRecordings.get() <= 0) {
                return;
            }
            try {
                Thread.sleep(QUIET_POLL_SLEEP_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    int inFlightCountForTests() {
        return inFlightRecordings.get();
    }
}
