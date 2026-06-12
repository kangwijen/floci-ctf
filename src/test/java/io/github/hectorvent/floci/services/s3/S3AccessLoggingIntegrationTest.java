package io.github.hectorvent.floci.services.s3;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class S3AccessLoggingIntegrationTest {

    private static final String SOURCE_BUCKET = "access-log-source-bucket";
    private static final String LOG_BUCKET = "access-log-target-bucket";
    private static final String LOG_PREFIX = "access-logs/";
    private static final String OBJECT_KEY = "logged-object.txt";
    private static final String OBJECT_BODY = "access-log-payload";

    @Test
    @Order(1)
    void createBuckets() {
        given().put("/" + LOG_BUCKET).then().statusCode(200);
        given().put("/" + SOURCE_BUCKET).then().statusCode(200);
    }

    @Test
    @Order(2)
    void getLoggingBeforePutReturnsEmptyConfiguration() {
        given()
            .queryParam("logging", "")
        .when()
            .get("/" + SOURCE_BUCKET)
        .then()
            .statusCode(200)
            .body(containsString("<BucketLoggingStatus"))
            .body(not(containsString("<LoggingEnabled>")));
    }

    @Test
    @Order(3)
    void putBucketLogging() {
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
    @Order(4)
    void getBucketLoggingReturnsConfiguration() {
        given()
            .queryParam("logging", "")
        .when()
            .get("/" + SOURCE_BUCKET)
        .then()
            .statusCode(200)
            .body(containsString("<LoggingEnabled>"))
            .body(containsString("<TargetBucket>" + LOG_BUCKET + "</TargetBucket>"))
            .body(containsString("<TargetPrefix>" + LOG_PREFIX + "</TargetPrefix>"));
    }

    @Test
    @Order(5)
    void objectOperationsProduceAccessLogs() {
        given()
            .contentType("text/plain")
            .body(OBJECT_BODY)
        .when()
            .put("/" + SOURCE_BUCKET + "/" + OBJECT_KEY)
        .then()
            .statusCode(200);

        given()
        .when()
            .get("/" + SOURCE_BUCKET + "/" + OBJECT_KEY)
        .then()
            .statusCode(200)
            .body(containsString(OBJECT_BODY));

        given()
        .when()
            .get("/" + SOURCE_BUCKET)
        .then()
            .statusCode(200)
            .body(containsString("<ListBucketResult"));

        given()
        .when()
            .delete("/" + SOURCE_BUCKET + "/" + OBJECT_KEY)
        .then()
            .statusCode(204);

        String hourPrefix = LOG_PREFIX + DateTimeFormatter.ofPattern("yyyy-MM-dd-HH", Locale.ROOT)
                .withZone(ZoneOffset.UTC)
                .format(java.time.Instant.now());
        String logKey = given()
            .queryParam("prefix", hourPrefix)
        .when()
            .get("/" + LOG_BUCKET)
        .then()
            .statusCode(200)
            .extract()
            .xmlPath()
            .getString("ListBucketResult.Contents[0].Key");

        String logBody = given()
        .when()
            .get("/" + LOG_BUCKET + "/" + logKey)
        .then()
            .statusCode(200)
            .extract()
            .asString();

        List<String> lines = logBody.lines().filter(line -> !line.isBlank()).toList();
        assertTrue(lines.size() >= 4, "expected at least four access log lines");

        String joined = String.join("\n", lines);
        assertTrue(joined.contains(SOURCE_BUCKET));
        assertTrue(joined.contains("REST.PUT.OBJECT"));
        assertTrue(joined.contains("REST.GET.OBJECT"));
        assertTrue(joined.contains("REST.GET.BUCKET"));
        assertTrue(joined.contains("REST.DELETE.OBJECT"));
        assertTrue(joined.contains(OBJECT_KEY));
        assertTrue(joined.contains("HTTP/1.1"));
    }

    @Test
    @Order(6)
    void deleteBucketLoggingClearsConfiguration() {
        given()
            .queryParam("logging", "")
        .when()
            .delete("/" + SOURCE_BUCKET)
        .then()
            .statusCode(204);

        given()
            .queryParam("logging", "")
        .when()
            .get("/" + SOURCE_BUCKET)
        .then()
            .statusCode(200)
            .body(containsString("<BucketLoggingStatus"))
            .body(not(containsString("<LoggingEnabled>")));
    }

    @Test
    @Order(7)
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
}
