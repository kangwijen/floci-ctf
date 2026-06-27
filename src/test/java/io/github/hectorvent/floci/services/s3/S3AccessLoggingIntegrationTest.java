package io.github.hectorvent.floci.services.s3;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.List;
import java.util.regex.Pattern;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
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
    private static final Pattern SIMPLE_LOG_KEY = Pattern.compile(
            "access-logs/\\d{4}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-[0-9a-f]{16}");

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
    void putBucketLoggingWithSimplePrefixFormat() {
        String xml = """
                <BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                    <LoggingEnabled>
                        <TargetBucket>%s</TargetBucket>
                        <TargetPrefix>%s</TargetPrefix>
                        <TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat>
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
            .body(containsString("<TargetPrefix>" + LOG_PREFIX + "</TargetPrefix>"))
            .body(containsString("<SimplePrefix"));
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

        List<String> keys = given()
            .queryParam("prefix", LOG_PREFIX)
        .when()
            .get("/" + LOG_BUCKET)
        .then()
            .statusCode(200)
            .body("ListBucketResult.Contents.size()", greaterThanOrEqualTo(4))
            .extract()
            .xmlPath()
            .getList("ListBucketResult.Contents.Key", String.class);

        assertTrue(keys.stream().allMatch(key -> SIMPLE_LOG_KEY.matcher(key).matches()),
                "unexpected log object keys: " + keys);

        StringBuilder joined = new StringBuilder();
        for (String key : keys) {
            joined.append(given().when().get("/" + LOG_BUCKET + "/" + key).then().statusCode(200).extract().asString());
        }
        String logBody = joined.toString();
        assertTrue(logBody.lines().filter(line -> !line.isBlank()).count() >= 4);

        assertTrue(logBody.contains(SOURCE_BUCKET));
        assertTrue(logBody.contains("REST.PUT.OBJECT"));
        assertTrue(logBody.contains("REST.GET.OBJECT"));
        assertTrue(logBody.contains("REST.GET.BUCKET"));
        assertTrue(logBody.contains("REST.DELETE.OBJECT"));
        assertTrue(logBody.contains(OBJECT_KEY));
        assertTrue(logBody.contains("HTTP/1.1"));
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
