package io.github.hectorvent.floci.services.apigateway;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static io.restassured.RestAssured.*;
import static org.hamcrest.Matchers.*;

/**
 * Verifies {@code CreateDeployment} with {@code stageName} auto-creates a stage
 * visible in {@code GetStages}, and {@code TestInvokeMethod} executes MOCK and
 * {@code AWS_PROXY} integrations without deploying to a stage.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ApiGatewayDeploymentAndTestInvokeIntegrationTest {

    private static final String LAMBDA_BASE_PATH = "/2015-03-31/functions";
    private static final String PROXY_FUNCTION = "apigw-test-invoke-fn";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/lambda-role";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";

    private static String apiId;
    private static String rootId;
    private static String resourceId;
    private static String proxyResourceId;
    private static String deploymentId;

    @Test @Order(1)
    void createRestApi() {
        apiId = given()
                .contentType(ContentType.JSON)
                .body("{\"name\":\"apigw-test-invoke\"}")
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
                .body("{\"pathPart\":\"mock\"}")
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
                .body("{\"description\":\"stage-deploy\",\"stageName\":\"v1\"}")
                .when().post("/restapis/" + apiId + "/deployments")
                .then()
                .statusCode(201)
                .body("id", notNullValue())
                .body("description", equalTo("stage-deploy"))
                .extract().path("id");

        given()
                .when().get("/restapis/" + apiId + "/stages/v1")
                .then()
                .statusCode(200)
                .body("stageName", equalTo("v1"))
                .body("deploymentId", equalTo(deploymentId));

        given()
                .when().get("/restapis/" + apiId + "/stages")
                .then()
                .statusCode(200)
                .body("item.stageName", hasItem("v1"));
    }

    @Test @Order(4)
    void testInvokeMethodPostReturns200WithMockIntegration() {
        String body = """
                {
                  "resourceId": "%s",
                  "httpMethod": "POST",
                  "pathWithQueryString": "/mock",
                  "headers": {"Content-Type": "application/json"},
                  "body": "{\\"payload\\":\\"data\\"}"
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
    void setupAwsProxyIntegrationForTestInvoke() throws Exception {
        createNodeLambda(PROXY_FUNCTION, """
                exports.handler = async () => ({
                  statusCode: 200,
                  body: "ok"
                });
                """);

        proxyResourceId = given()
                .contentType(ContentType.JSON)
                .body("{\"pathPart\":\"echo\"}")
                .when().post("/restapis/" + apiId + "/resources/" + rootId)
                .then()
                .statusCode(201)
                .extract().path("id");

        given()
                .contentType(ContentType.JSON)
                .body("{\"authorizationType\":\"NONE\"}")
                .when().put("/restapis/" + apiId + "/resources/" + proxyResourceId + "/methods/GET")
                .then()
                .statusCode(201);

        String proxyUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + PROXY_FUNCTION + "/invocations";

        given()
                .contentType(ContentType.JSON)
                .body("{\"type\":\"AWS_PROXY\",\"httpMethod\":\"POST\",\"uri\":\"" + proxyUri + "\"}")
                .when().put("/restapis/" + apiId + "/resources/" + proxyResourceId + "/methods/GET/integration")
                .then()
                .statusCode(201);
    }

    @Test @Order(6)
    void testInvokeMethodGetReturns200WithAwsProxyIntegration() {
        String body = """
                {
                  "resourceId": "%s",
                  "httpMethod": "GET",
                  "pathWithQueryString": "/echo"
                }
                """.formatted(proxyResourceId);

        given()
                .contentType(ContentType.JSON)
                .body(body)
                .when().post("/restapis/" + apiId + "/test-invoke-method")
                .then()
                .statusCode(200)
                .body("status", equalTo(200))
                .body("body", equalTo("ok"));
    }

    @Test @Order(7)
    void cleanup() {
        given().when().delete("/restapis/" + apiId).then().statusCode(202);
        given().when().delete(LAMBDA_BASE_PATH + "/" + PROXY_FUNCTION).then().statusCode(anyOf(is(204), is(404)));
    }

    private static void createNodeLambda(String functionName, String handlerSource) throws Exception {
        String zipBase64 = Base64.getEncoder().encodeToString(zipEntries(Map.of(
                "index.js", handlerSource
        )));

        given()
                .contentType(ContentType.JSON)
                .body("""
                        {
                          "FunctionName":"%s",
                          "Runtime":"nodejs20.x",
                          "Role":"%s",
                          "Handler":"index.handler",
                          "Timeout":30,
                          "Code":{"ZipFile":"%s"}
                        }
                        """.formatted(functionName, ROLE_ARN, zipBase64))
                .when().post(LAMBDA_BASE_PATH)
                .then()
                .statusCode(201);
    }

    private static byte[] zipEntries(Map<String, String> entries) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, String> entry : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(entry.getKey()));
                zos.write(entry.getValue().getBytes(StandardCharsets.UTF_8));
                zos.closeEntry();
            }
        }
        return baos.toByteArray();
    }
}
