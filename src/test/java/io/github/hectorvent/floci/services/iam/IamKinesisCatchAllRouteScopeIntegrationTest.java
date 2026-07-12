package io.github.hectorvent.floci.services.iam;

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
 * Regression: catch-all / bucket-style S3 REST rules must not claim other REST services.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamKinesisCatchAllRouteScopeIntegrationTest {

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String s3PlayerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "kinesis-catchall-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);
        CtfLabIamTestSupport.putUserPolicy(user, "kinesis-only", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"kinesis:*","Resource":"*"},
              {"Effect":"Deny","Action":"apigatewayv2:*","Resource":"*"}
            ]}""");

        String s3User = "s3-bucket-style-scope-test-user";
        CtfLabIamTestSupport.createUser(s3User);
        s3PlayerAkid = CtfLabIamTestSupport.createAccessKey(s3User);
        CtfLabIamTestSupport.putUserPolicy(s3User, "s3-only", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:*","Resource":"*"},
              {"Effect":"Deny","Action":"appconfig:*","Resource":"*"},
              {"Effect":"Deny","Action":"lambda:*","Resource":"*"}
            ]}""");
    }

    @Test
    void kinesisScopedPostV2ApisDeniedDespiteKinesisAllow() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "kinesis"))
                .contentType("application/json")
                .body("{\"name\":\"collision-api\",\"protocolType\":\"HTTP\"}")
        .when()
                .post("/v2/apis")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void s3ScopedGetApplicationsDeniedAsAppConfigRoute() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(s3PlayerAkid, "s3"))
                .contentType("application/json")
        .when()
                .get("/applications/scope-collision-app")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void s3ScopedLambdaDatedApiDeniedAsLambdaRoute() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(s3PlayerAkid, "s3"))
                .contentType("application/json")
        .when()
                .delete("/2017-10-31/functions/scope-collision-fn/concurrency")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }
}
