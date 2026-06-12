package io.github.hectorvent.floci.services.guardduty;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
class GuardDutyIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = "GuardDuty_2017-11-28.";

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @Test
    void detectorAndSampleFindingsLifecycle() {
        given()
                .header("X-Amz-Target", TARGET_PREFIX + "ListDetectors")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("detectorIds", hasSize(0));

        String detectorId = given()
                .header("X-Amz-Target", TARGET_PREFIX + "CreateDetector")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "enable": true,
                            "findingPublishingFrequency": "ONE_HOUR",
                            "tags": {"lab": "forensic"}
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("detectorId", notNullValue())
                .extract().jsonPath().getString("detectorId");

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "CreateDetector")
                .contentType(CONTENT_TYPE)
                .body("{\"enable\": true}")
        .when()
                .post("/")
        .then()
                .statusCode(400);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "ListDetectors")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("detectorIds", hasSize(1))
                .body("detectorIds[0]", equalTo(detectorId));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "GetDetector")
                .contentType(CONTENT_TYPE)
                .body("""
                        {"DetectorId": "%s"}
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("status", equalTo("ENABLED"))
                .body("findingPublishingFrequency", equalTo("ONE_HOUR"))
                .body("dataSources.cloudTrail.status", equalTo("ENABLED"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "UpdateDetector")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "enable": false,
                            "findingPublishingFrequency": "SIX_HOURS"
                        }
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "GetDetector")
                .contentType(CONTENT_TYPE)
                .body("""
                        {"DetectorId": "%s"}
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("status", equalTo("DISABLED"))
                .body("findingPublishingFrequency", equalTo("SIX_HOURS"));

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "UpdateDetector")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "enable": true
                        }
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "CreateSampleFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "findingTypes": [
                                "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                                "CryptoCurrency:EC2/BitcoinTool.B"
                            ]
                        }
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        String findingId = given()
                .header("X-Amz-Target", TARGET_PREFIX + "ListFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "maxResults": 10
                        }
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("findingIds", hasSize(greaterThanOrEqualTo(2)))
                .extract().jsonPath().getString("findingIds[0]");

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "GetFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "findingIds": ["%s"]
                        }
                        """.formatted(detectorId, findingId))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("findings", hasSize(1))
                .body("findings[0].id", equalTo(findingId))
                .body("findings[0].arn", startsWith("arn:aws:guardduty:"))
                .body("findings[0].type", notNullValue())
                .body("findings[0].severity", greaterThanOrEqualTo(1.0f))
                .body("findings[0].resource", notNullValue())
                .body("findings[0].service.action.actionType", notNullValue());

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "ArchiveFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "findingIds": ["%s"]
                        }
                        """.formatted(detectorId, findingId))
        .when()
                .post("/")
        .then()
                .statusCode(200);

        given()
                .header("X-Amz-Target", TARGET_PREFIX + "ListFindings")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "DetectorId": "%s",
                            "findingCriteria": {
                                "criterion": {
                                    "service.archived": {"equals": ["true"]}
                                }
                            }
                        }
                        """.formatted(detectorId))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("findingIds", hasSize(greaterThanOrEqualTo(1)));
    }
}
