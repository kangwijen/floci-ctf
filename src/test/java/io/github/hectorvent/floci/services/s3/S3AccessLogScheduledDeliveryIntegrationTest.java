package io.github.hectorvent.floci.services.s3;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(S3AccessLogScheduledDeliveryIntegrationTest.Profile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class S3AccessLogScheduledDeliveryIntegrationTest {

    private static final String SOURCE_BUCKET = "scheduled-access-log-source";
    private static final String LOG_BUCKET = "scheduled-access-log-target";
    private static final String LOG_PREFIX = "scheduled-logs/";
    private static final String OBJECT_KEY = "batched-object.txt";

    @Inject
    S3AccessLogService accessLogService;

    @Test
    @Order(1)
    void createBucketsAndEnableLogging() {
        given().put("/" + LOG_BUCKET).then().statusCode(200);
        given().put("/" + SOURCE_BUCKET).then().statusCode(200);

        String xml = """
                <BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <LoggingEnabled>
                        <TargetBucket>%s</TargetBucket>
                        <TargetPrefix>%s</TargetPrefix>
                    </LoggingEnabled>
                </BucketLoggingStatus>
                """.formatted(LOG_BUCKET, LOG_PREFIX);

        given()
                .queryParam("logging", "")
                .contentType("application/xml")
                .body(xml)
        .when()
                .put("/" + SOURCE_BUCKET)
        .then()
                .statusCode(200);
    }

    @Test
    @Order(2)
    void scheduledModeBatchesLinesIntoSingleObjectOnFlush() throws Exception {
        given().contentType("text/plain").body("one").put("/" + SOURCE_BUCKET + "/" + OBJECT_KEY).then().statusCode(200);
        given().when().get("/" + SOURCE_BUCKET + "/" + OBJECT_KEY).then().statusCode(200);
        given().when().delete("/" + SOURCE_BUCKET + "/" + OBJECT_KEY).then().statusCode(204);

        accessLogService.flushAllBuffersForTests();
        TimeUnit.MILLISECONDS.sleep(1200L);
        accessLogService.flushAllBuffersForTests();

        List<String> keys = given()
                .queryParam("prefix", LOG_PREFIX)
        .when()
                .get("/" + LOG_BUCKET)
        .then()
                .statusCode(200)
                .body("ListBucketResult.Contents.size()", greaterThanOrEqualTo(1))
                .extract()
                .xmlPath()
                .getList("ListBucketResult.Contents.Key", String.class);

        String logBody = given()
        .when()
                .get("/" + LOG_BUCKET + "/" + keys.getFirst())
        .then()
                .statusCode(200)
                .extract()
                .asString();

        List<String> lines = logBody.lines().filter(line -> !line.isBlank()).toList();
        assertTrue(lines.size() >= 3, "expected batched log lines, got: " + lines.size());
        assertTrue(logBody.contains("REST.PUT.OBJECT"));
        assertTrue(logBody.contains("REST.GET.OBJECT"));
        assertTrue(logBody.contains("REST.DELETE.OBJECT"));
    }

    @Test
    @Order(3)
    void cleanup() {
        given().delete("/" + SOURCE_BUCKET);
        given()
                .queryParam("prefix", LOG_PREFIX)
        .when()
                .get("/" + LOG_BUCKET)
        .then()
                .statusCode(200)
                .extract()
                .xmlPath()
                .getList("ListBucketResult.Contents.Key", String.class)
                .forEach(key -> given().delete("/" + LOG_BUCKET + "/" + key));
        given().delete("/" + LOG_BUCKET);
    }

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.s3.access-log-delivery-mode", "scheduled",
                    "floci.services.s3.access-log-delivery-interval-seconds", "1");
        }
    }
}
