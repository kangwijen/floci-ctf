package io.github.hectorvent.floci.services.apigateway;

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
 * Regression: SigV4 credential scope must match the REST route service.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiGatewayIamScopeBypassIntegrationTest {

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "apigw-scope-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);
        CtfLabIamTestSupport.putUserPolicy(user, "iam-only", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:*","Resource":"*"}
            ]}""");
    }

    @Test
    void iamScopedPostRestapisDeniedDespiteIamAllow() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "iam"))
                .contentType("application/json")
                .body("{\"name\":\"bypass-api\"}")
        .when()
                .post("/restapis")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    @Test
    void apigatewayScopedPostRestapisDeniedWithoutApigwPolicy() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"name\":\"legit-api\"}")
        .when()
                .post("/restapis")
        .then()
                .statusCode(403);
    }
}
