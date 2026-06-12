package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.testsupport.CloudTrailAuditProfile;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

/**
 * Mutating CloudTrail control-plane calls are audited even after logging stops.
 */
@QuarkusTest
@TestProfile(CloudTrailAuditProfile.class)
class CloudTrailTamperingAuditIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";

    @Inject
    CloudTrailEventStore eventStore;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @BeforeEach
    void resetStore() {
        eventStore.clear();
    }

    @Test
    void stopLoggingRecordedInLookupEventsWhenTrailWasLogging() {
        String trailBucket = "cloudtrail-tamper-audit-bucket";
        String trailName = "tamper-audit-trail";

        given().when().put("/" + trailBucket).then().statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s",
                            "S3BucketName": "%s"
                        }
                        """.formatted(trailName, trailBucket))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s"
                        }
                        """.formatted(trailName))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "StopLogging")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "Name": "%s"
                        }
                        """.formatted(trailName))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {
                                    "AttributeKey": "EventName",
                                    "AttributeValue": "StopLogging"
                                }
                            ]
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo("StopLogging"))
                .body("Events[0].EventSource", equalTo("cloudtrail.amazonaws.com"));
    }
}
