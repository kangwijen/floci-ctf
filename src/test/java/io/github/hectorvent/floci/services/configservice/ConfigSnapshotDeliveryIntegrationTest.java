package io.github.hectorvent.floci.services.configservice;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ConfigSnapshotDeliveryIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "StarlingDoveService.";

    private static String configBucket;
    private static String configUser;
    private static String snapshotS3Key;

    @Inject
    S3Service s3Service;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        long suffix = System.currentTimeMillis();
        configBucket = "config-snapshot-delivery-" + suffix;
        configUser = "config-snapshot-user-" + suffix;
    }

    @Test
    @Order(1)
    void provisionResourcesAndRecorder() {
        s3Service.createBucket(configBucket, "us-east-1");

        given()
            .formParam("Action", "CreateUser")
            .formParam("UserName", configUser)
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .header("X-Amz-Target", TARGET_PREFIX + "PutConfigurationRecorder")
            .contentType(CONTENT_TYPE)
            .body("""
                {
                    "ConfigurationRecorder": {
                        "name": "default",
                        "roleARN": "arn:aws:iam::000000000000:role/config-role",
                        "recordingGroup": {
                            "allSupported": true,
                            "includeGlobalResourceTypes": false
                        }
                    }
                }
                """)
        .when()
            .post("/")
        .then()
            .statusCode(200);

        given()
            .header("X-Amz-Target", TARGET_PREFIX + "PutDeliveryChannel")
            .contentType(CONTENT_TYPE)
            .body("""
                {
                    "DeliveryChannel": {
                        "name": "default",
                        "s3BucketName": "%s",
                        "s3KeyPrefix": "config-snapshots"
                    }
                }
                """.formatted(configBucket))
        .when()
            .post("/")
        .then()
            .statusCode(200);
    }

    @Test
    @Order(2)
    void startRecorderDeliversSnapshotToS3() throws Exception {
        given()
            .header("X-Amz-Target", TARGET_PREFIX + "StartConfigurationRecorder")
            .contentType(CONTENT_TYPE)
            .body("""
                {"ConfigurationRecorderName": "default"}
                """)
        .when()
            .post("/")
        .then()
            .statusCode(200);

        List<S3Object> objects = s3Service.listObjects(configBucket, "config-snapshots/AWSLogs/", null, 100);
        assertFalse(objects.isEmpty(), "expected Config snapshot object in delivery bucket");
        S3Object snapshotObject = objects.stream()
                .filter(o -> o.getKey().contains("ConfigSnapshot-") && o.getKey().endsWith(".json"))
                .findFirst()
                .orElseThrow();
        snapshotS3Key = snapshotObject.getKey();
        assertTrue(snapshotS3Key.startsWith("config-snapshots/AWSLogs/000000000000/Config/ConfigSnapshot/"));
        assertTrue(snapshotS3Key.contains("/ConfigSnapshot-"));
        assertTrue(snapshotS3Key.endsWith(".json"));

        S3Object stored = s3Service.getObject(configBucket, snapshotS3Key);
        JsonNode snapshot = objectMapper.readTree(new String(stored.getData(), StandardCharsets.UTF_8));
        assertTrue(snapshot.has("configurationItems"));
        assertTrue(snapshot.get("configurationItems").size() >= 1);
    }

    @Test
    @Order(3)
    void getResourceConfigHistoryReturnsIamUserItem() throws Exception {
        given()
            .header("X-Amz-Target", TARGET_PREFIX + "GetResourceConfigHistory")
            .contentType(CONTENT_TYPE)
            .body("""
                {
                    "resourceType": "AWS::IAM::User",
                    "resourceId": "%s",
                    "limit": 10
                }
                """.formatted(configUser))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("configurationItems", hasSize(greaterThanOrEqualTo(1)))
            .body("configurationItems[0].resourceType", equalTo("AWS::IAM::User"))
            .body("configurationItems[0].resourceId", equalTo(configUser))
            .body("configurationItems[0].configurationItemStatus", equalTo("OK"));
    }

    @Test
    @Order(4)
    void batchGetResourceConfigReturnsLatestItems() {
        given()
            .header("X-Amz-Target", TARGET_PREFIX + "BatchGetResourceConfig")
            .contentType(CONTENT_TYPE)
            .body("""
                {
                    "resourceKeys": [
                        {
                            "resourceType": "AWS::IAM::User",
                            "resourceId": "%s"
                        },
                        {
                            "resourceType": "AWS::S3::Bucket",
                            "resourceId": "%s"
                        }
                    ]
                }
                """.formatted(configUser, configBucket))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("baseConfigurationItems", hasSize(2))
            .body("baseConfigurationItems.resourceType", hasItems("AWS::IAM::User", "AWS::S3::Bucket"))
            .body("unprocessedResourceKeys", hasSize(0));
    }

    @Test
    @Order(5)
    void deliverConfigurationSnapshotCanBeInvokedExplicitly() {
        given()
            .header("X-Amz-Target", TARGET_PREFIX + "DeliverConfigurationSnapshot")
            .contentType(CONTENT_TYPE)
            .body("{}")
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("snapshotId", notNullValue());

        List<S3Object> objects = s3Service.listObjects(configBucket, "config-snapshots/AWSLogs/", null, 100);
        assertTrue(objects.size() >= 2, "expected a second snapshot after explicit delivery");
    }
}
