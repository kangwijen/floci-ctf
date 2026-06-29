package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEventResource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CloudTrailEventStoreTest {

    private CloudTrailEventStore store;

    @BeforeEach
    void setUp() {
        store = new CloudTrailEventStore(new InMemoryStorage<>());
    }

    @Test
    void lookupSortsMostRecentFirstAndFiltersByAttribute() {
        store.store(event("CreateBucket", "alice", "s3.amazonaws.com", false,
                Instant.parse("2024-06-01T10:00:00Z"), "arn:aws:s3:::bucket"));
        store.store(event("GetObject", "bob", "s3.amazonaws.com", true,
                Instant.parse("2024-06-01T11:00:00Z"), "arn:aws:s3:::bucket/key"));

        CloudTrailEventStore.LookupEventsResult result = store.lookup(
                "us-east-1",
                null,
                null,
                List.of(new CloudTrailEventStore.LookupAttribute("EventName", "GetObject")),
                50,
                null);

        assertEquals(1, result.events().size());
        assertEquals("GetObject", result.events().get(0).getEventName());
    }

    @Test
    void lookupPaginatesWithNextToken() {
        for (int i = 0; i < 3; i++) {
            store.store(event("Event" + i, "user", "s3.amazonaws.com", false,
                    Instant.parse("2024-06-01T10:00:0" + i + "Z"), "arn:aws:s3:::bucket/" + i));
        }

        CloudTrailEventStore.LookupEventsResult first = store.lookup(
                "us-east-1", null, null, List.of(), 2, null);
        assertEquals(2, first.events().size());
        assertEquals("Event2", first.events().get(0).getEventName());

        CloudTrailEventStore.LookupEventsResult second = store.lookup(
                "us-east-1", null, null, List.of(), 2, first.nextToken());
        assertEquals(1, second.events().size());
        assertNull(second.nextToken());
    }

    @Test
    void lookupPaginationDoesNotDuplicateEventsWithSameEventTimeAndSequence() {
        Instant sameTime = Instant.parse("2024-06-01T10:00:00.123Z");
        for (int i = 0; i < 7; i++) {
            store.store(event("Event" + i, "user", "s3.amazonaws.com", false, sameTime,
                    "arn:aws:s3:::bucket/key-" + i, 0));
        }

        Set<String> seen = new HashSet<>();
        List<String> ordered = new ArrayList<>();
        String nextToken = null;
        for (int page = 0; page < 10; page++) {
            CloudTrailEventStore.LookupEventsResult result = store.lookup(
                    "us-east-1", null, null, List.of(), 2, nextToken);
            for (CloudTrailEvent event : result.events()) {
                assertTrue(seen.add(event.getEventId()),
                        () -> "Duplicate EventId in lookup pagination: " + event.getEventId());
                ordered.add(event.getEventName());
            }
            if (result.nextToken() == null) {
                assertEquals(7, seen.size());
                break;
            }
            nextToken = result.nextToken();
        }
        assertEquals(7, ordered.size());
    }

    @Test
    void lookupPaginationDoesNotDuplicateWhenNewEventsArriveBetweenPages() {
        Instant base = Instant.parse("2024-06-01T10:00:00Z");
        for (int i = 0; i < 5; i++) {
            store.store(event("Baseline" + i, "user", "s3.amazonaws.com", false,
                    base.plusSeconds(i), "arn:aws:s3:::bucket/" + i));
        }

        CloudTrailEventStore.LookupEventsResult first = store.lookup(
                "us-east-1", null, null, List.of(), 2, null);
        assertEquals(2, first.events().size());

        store.store(event("Newest", "user", "s3.amazonaws.com", false,
                base.plusSeconds(10), "arn:aws:s3:::bucket/newest"));

        Set<String> seen = new HashSet<>();
        for (CloudTrailEvent event : first.events()) {
            seen.add(event.getEventId());
        }

        String nextToken = first.nextToken();
        while (nextToken != null) {
            CloudTrailEventStore.LookupEventsResult page = store.lookup(
                    "us-east-1", null, null, List.of(), 2, nextToken);
            for (CloudTrailEvent event : page.events()) {
                assertTrue(seen.add(event.getEventId()),
                        () -> "Duplicate EventId after concurrent insert: " + event.getEventId());
            }
            nextToken = page.nextToken();
        }
        assertEquals(5, seen.size());

        CloudTrailEventStore.LookupEventsResult fresh = store.lookup(
                "us-east-1", null, null, List.of(), 10, null);
        assertEquals(6, fresh.events().size());
    }

    @Test
    void lookupSortsSameEventTimeBySequenceDescending() {
        Instant sameTime = Instant.parse("2024-06-01T10:00:00.123Z");
        store.store(event("First", "user", "s3.amazonaws.com", false, sameTime,
                "arn:aws:s3:::bucket/key-1", 1));
        store.store(event("Second", "user", "s3.amazonaws.com", false, sameTime,
                "arn:aws:s3:::bucket/key-2", 2));
        store.store(event("Third", "user", "s3.amazonaws.com", false, sameTime,
                "arn:aws:s3:::bucket/key-3", 3));

        CloudTrailEventStore.LookupEventsResult result = store.lookup(
                "us-east-1", null, null, List.of(), 50, null);

        assertEquals(3, result.events().size());
        assertEquals("Third", result.events().get(0).getEventName());
        assertEquals("Second", result.events().get(1).getEventName());
        assertEquals("First", result.events().get(2).getEventName());
    }

    @Test
    void lookupRejectsInvalidMaxResults() {
        assertThrows(io.github.hectorvent.floci.core.common.AwsException.class,
                () -> store.lookup("us-east-1", null, null, List.of(), 51, null));
    }

    @Test
    void lookupRejectsLegacyOffsetNextToken() {
        String legacyOffsetToken = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("2".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertThrows(io.github.hectorvent.floci.core.common.AwsException.class,
                () -> store.lookup("us-east-1", null, null, List.of(), 2, legacyOffsetToken));
    }

    private static CloudTrailEvent event(String name,
                                         String username,
                                         String source,
                                         boolean readOnly,
                                         Instant time,
                                         String resourceArn) {
        return event(name, username, source, readOnly, time, resourceArn, 0);
    }

    private static CloudTrailEvent event(String name,
                                         String username,
                                         String source,
                                         boolean readOnly,
                                         Instant time,
                                         String resourceArn,
                                         long sequence) {
        CloudTrailEvent event = new CloudTrailEvent();
        event.setEventId(name + "-id");
        event.setRegion("us-east-1");
        event.setEventName(name);
        event.setUsername(username);
        event.setEventSource(source);
        event.setReadOnly(readOnly);
        event.setEventTime(time);
        event.setSequence(sequence);
        event.setResourceArn(resourceArn);
        event.setResources(List.of(new CloudTrailEventResource(resourceArn, "AWS::S3::Object")));
        event.setFullEventJson("{\"eventName\":\"" + name + "\"}");
        return event;
    }
}
