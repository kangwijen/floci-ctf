package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code cloudtrail:StopLogging} scoped to one trail ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloudTrailIamScopedIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = CtfLabIamTestSupport.CLOUDTRAIL_TARGET_PREFIX;
    private static final String REGION = "us-east-1";
    private static final String ALLOWED_TRAIL = "ctf-allowed-trail";
    private static final String DECOY_TRAIL = "ctf-decoy-trail";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-cloudtrail-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "cloudtrail");

        createTrail(rootAuth, ALLOWED_TRAIL, "ctf-allowed-trail-logs");
        startLogging(rootAuth, ALLOWED_TRAIL);
        createTrail(rootAuth, DECOY_TRAIL, "ctf-decoy-trail-logs");
        startLogging(rootAuth, DECOY_TRAIL);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"cloudtrail:StopLogging",
               "Resource":"arn:aws:cloudtrail:%s:%s:trail/%s"}
            ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_TRAIL);
        CtfLabIamTestSupport.putUserPolicy(user, "stop-one-trail", policy);
    }

    @Test
    void stopAllowedTrail() {
        given()
                .header("Authorization", playerCloudTrailAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "StopLogging")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"" + ALLOWED_TRAIL + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    @Test
    void stopDecoyTrailDenied() {
        given()
                .header("Authorization", playerCloudTrailAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "StopLogging")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"" + DECOY_TRAIL + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void createTrail(String auth, String name, String bucket) {
        given().header("Authorization", auth).when().put("/" + bucket).then().statusCode(200);
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("""
                        {"Name":"%s","S3BucketName":"%s"}
                        """.formatted(name, bucket))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static void startLogging(String auth, String name) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"" + name + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private String playerCloudTrailAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "cloudtrail");
    }
}
