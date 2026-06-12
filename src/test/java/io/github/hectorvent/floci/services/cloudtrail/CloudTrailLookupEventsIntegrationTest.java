package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEvent;
import io.github.hectorvent.floci.services.cloudtrail.model.CloudTrailEventResource;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

@QuarkusTest
class CloudTrailLookupEventsIntegrationTest {
    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String REGION = "us-east-1";

    @Inject
    CloudTrailEventStore eventStore;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @BeforeEach
    void seedEvents() {
        eventStore.clear();
        storeEvent("CreateBucket", "s3.amazonaws.com", "alice",
                "arn:aws:s3:::audit-bucket", "AWS::S3::Bucket", false,
                Instant.parse("2024-06-01T10:00:00Z"));
        storeEvent("GetObject", "s3.amazonaws.com", "bob",
                "arn:aws:s3:::audit-bucket/object.txt", "AWS::S3::Object", true,
                Instant.parse("2024-06-01T11:00:00Z"));
        storeEvent("CreateTrail", "cloudtrail.amazonaws.com", "alice",
                "arn:aws:cloudtrail:us-east-1:000000000000:trail/audit", "AWS::CloudTrail::Trail", false,
                Instant.parse("2024-06-01T12:00:00Z"));
    }

    private void storeEvent(String eventName,
                            String eventSource,
                            String username,
                            String resourceArn,
                            String resourceType,
                            boolean readOnly,
                            Instant eventTime) {
        CloudTrailEvent event = new CloudTrailEvent();
        event.setEventId(java.util.UUID.randomUUID().toString());
        event.setRegion(REGION);
        event.setEventName(eventName);
        event.setEventSource(eventSource);
        event.setUsername(username);
        event.setResourceArn(resourceArn);
        event.setResourceType(resourceType);
        event.setReadOnly(readOnly);
        event.setEventTime(eventTime);
        event.setResources(List.of(new CloudTrailEventResource(resourceArn, resourceType)));
        event.setFullEventJson("""
                {"eventName":"%s","eventSource":"%s","userName":"%s","readOnly":%s}
                """.formatted(eventName, eventSource, username, readOnly).trim());
        eventStore.store(event);
    }

    @Test
    void lookupEventsReturnsEventsSortedMostRecentFirst() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "StartTime": 1717236000.0,
                            "EndTime": 1717243200.0
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(3))
                .body("Events[0].EventName", equalTo("CreateTrail"))
                .body("Events[1].EventName", equalTo("GetObject"))
                .body("Events[2].EventName", equalTo("CreateBucket"))
                .body("Events[0].EventSource", equalTo("cloudtrail.amazonaws.com"))
                .body("Events[0].Username", equalTo("alice"))
                .body("Events[0].CloudTrailEvent", containsString("CreateTrail"))
                .body("Events[0].Resources[0].ResourceName", equalTo(
                        "arn:aws:cloudtrail:us-east-1:000000000000:trail/audit"));
    }

    @Test
    void lookupEventsFiltersByEventName() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "EventName",
                                    "AttributeValue": "GetObject"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo("GetObject"))
                .body("Events[0].ReadOnly", equalTo("true"));
    }

    @Test
    void lookupEventsFiltersByUsernameAndEventSource() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "Username",
                                    "AttributeValue": "alice"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(2))
                .body("Events[0].EventName", equalTo("CreateTrail"))
                .body("Events[1].EventName", equalTo("CreateBucket"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "EventSource",
                                    "AttributeValue": "s3.amazonaws.com"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(2))
                .body("Events[0].EventName", equalTo("GetObject"))
                .body("Events[1].EventName", equalTo("CreateBucket"));
    }

    @Test
    void lookupEventsFiltersByResourceNameAndReadOnly() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "ResourceName",
                                    "AttributeValue": "arn:aws:s3:::audit-bucket"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo("CreateBucket"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "ReadOnly",
                                    "AttributeValue": "true"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo("GetObject"));
    }

    @Test
    void lookupEventsPaginatesWithMaxResultsAndNextToken() {
        String nextToken = given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "MaxResults": 2
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(2))
                .body("Events[0].EventName", equalTo("CreateTrail"))
                .body("Events[1].EventName", equalTo("GetObject"))
                .body("NextToken", notNullValue())
                .extract().path("NextToken");

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "MaxResults": 2,
                            "NextToken": "%s"
                        }
                        """.formatted(nextToken))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(greaterThan(0)))
                .body("Events[0].EventName", equalTo("CreateBucket"))
                .body("NextToken", nullValue());
    }

    @Test
    void lookupEventsRejectsInvalidInput() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "StartTime": 1717243200.0,
                            "EndTime": 1717236000.0
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", containsString("InvalidTimeRangeException"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "MaxResults": 51
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", containsString("InvalidMaxResultsException"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {"AttributeKey": "NotAKey", "AttributeValue": "x"}
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", containsString("InvalidLookupAttributesException"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "NextToken": "not-valid"
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(400)
                .body("__type", containsString("InvalidNextTokenException"));
    }
}
