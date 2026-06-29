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
 * Data-plane invoke paths must require execute-api scope and execute-api:Invoke,
 * not apigateway:GET on /restapis/.../_user_request_/...
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiGatewayExecuteApiScopeIntegrationTest {

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-execapi-scope-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);
        CtfLabIamTestSupport.putUserPolicy(user, "apigw-control-only", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"apigateway:*","Resource":"*"},
              {"Effect":"Deny","Action":"execute-api:Invoke","Resource":"*"}
            ]}""");
    }

    @Test
    void userRequestPathDeniedWithApigatewayScopeWhenInvokeDenied() {
        String apiId = given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"name\":\"scope-test-api\"}")
        .when()
                .post("/restapis")
        .then()
                .statusCode(201)
                .extract().path("id");

        String rootId = given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
        .when()
                .get("/restapis/" + apiId + "/resources")
        .then()
                .statusCode(200)
                .extract().path("item[0].id");

        String resourceId = given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"pathPart\":\"probe\"}")
        .when()
                .post("/restapis/" + apiId + "/resources/" + rootId)
        .then()
                .statusCode(201)
                .extract().path("id");

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"authorizationType\":\"NONE\"}")
        .when()
                .put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET")
        .then()
                .statusCode(201);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"responseParameters\":{}}")
        .when()
                .put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/responses/200")
        .then()
                .statusCode(201);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"type\":\"MOCK\",\"requestTemplates\":{\"application/json\":\"{\\\"statusCode\\\": 200}\"}}")
        .when()
                .put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/integration")
        .then()
                .statusCode(201);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"selectionPattern\":\"\",\"responseTemplates\":{\"application/json\":\"{\\\"ok\\\":true}\"}}")
        .when()
                .put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/integration/responses/200")
        .then()
                .statusCode(201);

        String deploymentId = given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"description\":\"scope-test\"}")
        .when()
                .post("/restapis/" + apiId + "/deployments")
        .then()
                .statusCode(201)
                .extract().path("id");

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
                .contentType("application/json")
                .body("{\"stageName\":\"prod\",\"deploymentId\":\"" + deploymentId + "\"}")
        .when()
                .post("/restapis/" + apiId + "/stages")
        .then()
                .statusCode(201);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
        .when()
                .get("/restapis/" + apiId + "/prod/_user_request_/probe")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "apigateway"))
        .when()
                .delete("/restapis/" + apiId)
        .then()
                .statusCode(202);
    }
}
