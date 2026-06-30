package io.github.hectorvent.floci.services.apigateway;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Verifies {@code CreateDeployment} with {@code stageName} auto-creates a stage
 * visible in {@code GetStages}, and {@code TestInvokeMethod} executes MOCK
 * integrations without deploying to a stage.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ApiGatewayDeploymentAndTestInvokeIntegrationTest {

    private static String apiId;
    private static String rootId;
    private static String resourceId;
    private static String deploymentId;

    @Test @Order(1)
    void createRestApi() {
        apiId = given()
                .contentType(ContentType.JSON)
                .body("{\"name\":\"deployment-test-invoke-api\"}")
                .when().post("/restapis")
                .then()
                .statusCode(201)
                .body("id", notNullValue())
                .extract().path("id");
    }

    @Test @Order(2)
    void setupPostMockIntegration() {
        rootId = given()
                .when().get("/restapis/" + apiId + "/resources")
                .then()
                .statusCode(200)
                .extract().path("item[0].id");

        resourceId = given()
                .contentType(ContentType.JSON)
                .body("{\"pathPart\":\"items\"}")
                .when().post("/restapis/" + apiId + "/resources/" + rootId)
                .then()
                .statusCode(201)
                .extract().path("id");

        given()
                .contentType(ContentType.JSON)
                .body("{\"authorizationType\":\"NONE\"}")
                .when().put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/POST")
                .then()
                .statusCode(201);

        given()
                .contentType(ContentType.JSON)
                .body("{\"responseParameters\":{}}")
                .when().put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/POST/responses/200")
                .then()
                .statusCode(201);

        given()
                .contentType(ContentType.JSON)
                .body("{\"type\":\"MOCK\",\"requestTemplates\":{\"application/json\":\"{\\\"statusCode\\\": 200}\"}}")
                .when().put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/POST/integration")
                .then()
                .statusCode(201);

        given()
                .contentType(ContentType.JSON)
                .body("{\"selectionPattern\":\"\",\"responseTemplates\":{\"application/json\":\"{\\\"ok\\\":true}\"}}")
                .when().put("/restapis/" + apiId + "/resources/" + resourceId + "/methods/POST/integration/responses/200")
                .then()
                .statusCode(201);
    }

    @Test @Order(3)
    void createDeploymentWithStageNameCreatesStageVisibleInGetStages() {
        deploymentId = given()
                .contentType(ContentType.JSON)
                .body("{\"description\":\"prod-deploy\",\"stageName\":\"prod\"}")
                .when().post("/restapis/" + apiId + "/deployments")
                .then()
                .statusCode(201)
                .body("id", notNullValue())
                .body("description", equalTo("prod-deploy"))
                .extract().path("id");

        given()
                .when().get("/restapis/" + apiId + "/stages/prod")
                .then()
                .statusCode(200)
                .body("stageName", equalTo("prod"))
                .body("deploymentId", equalTo(deploymentId));

        given()
                .when().get("/restapis/" + apiId + "/stages")
                .then()
                .statusCode(200)
                .body("item.stageName", hasItem("prod"));
    }

    @Test @Order(4)
    void testInvokeMethodPostReturns200WithMockIntegration() {
        String body = """
                {
                  "resourceId": "%s",
                  "httpMethod": "POST",
                  "pathWithQueryString": "/items",
                  "headers": {"Content-Type": "application/json"},
                  "body": "{\\"name\\":\\"test\\"}"
                }
                """.formatted(resourceId);

        given()
                .contentType(ContentType.JSON)
                .body(body)
                .when().post("/restapis/" + apiId + "/test-invoke-method")
                .then()
                .statusCode(200)
                .body("status", equalTo(200))
                .body("body", containsString("\"ok\":true"));
    }

    @Test @Order(5)
    void cleanup() {
        given().when().delete("/restapis/" + apiId).then().statusCode(202);
    }
}
