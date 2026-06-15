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
import static org.hamcrest.Matchers.notNullValue;

/**
 * {@code cloudtrail:LookupEvents} scoped to {@code arn:aws:cloudtrail:REGION:ACCOUNT:trail/*}
 * when the JSON body has no trail name.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloudTrailLookupEventsScopedIamIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String TARGET_PREFIX = CtfLabIamTestSupport.CLOUDTRAIL_TARGET_PREFIX;
    private static final String REGION = "us-east-1";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "cloudtrail-lookup-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "cloudtrail");
        String trailBucket = "lookup-trail-logs";
        given().header("Authorization", rootAuth).when().put("/" + trailBucket).then().statusCode(200);
        createTrail(rootAuth, "lookup-trail", trailBucket);
        startLogging(rootAuth, "lookup-trail");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"cloudtrail:LookupEvents",
               "Resource":"arn:aws:cloudtrail:%s:%s:trail/*"}
            ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "lookup-trails", policy);
    }

    @Test
    void lookupEventsAllowedWithTrailWildcardResource() {
        given()
                .header("Authorization", playerCloudTrailAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("{\"MaxResults\":10}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Events", notNullValue());
    }

    @Test
    void lookupEventsDeniedWhenResourceIsSpecificTrailOnly() {
        String user = "cloudtrail-lookup-denied";
        CtfLabIamTestSupport.createUser(user);
        String akid = CtfLabIamTestSupport.createAccessKey(user);
        String narrowPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"cloudtrail:LookupEvents",
               "Resource":"arn:aws:cloudtrail:%s:%s:trail/other-trail"}
            ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "lookup-one-trail", narrowPolicy);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(akid, "cloudtrail"))
                .header("X-Amz-Target", TARGET_PREFIX + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void createTrail(String auth, String name, String bucket) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\",\"S3BucketName\":\"%s\"}".formatted(name, bucket))
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
                .body("{\"Name\":\"%s\"}".formatted(name))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private String playerCloudTrailAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "cloudtrail");
    }
}
