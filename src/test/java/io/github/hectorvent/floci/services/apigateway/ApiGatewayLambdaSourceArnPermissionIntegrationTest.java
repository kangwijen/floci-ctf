package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * API Gateway {@code AWS_PROXY} invoke passes {@code aws:SourceArn} resource policy checks
 * when the function permission scopes {@code apigateway.amazonaws.com} to the REST API.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiGatewayLambdaSourceArnPermissionIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final String APIGW_SERVICE = "apigateway";
    private static final String LAMBDA_SERVICE = "lambda";
    private static final String FUNCTION = "apigw-source-arn-fn";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/lambda-role";

    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;
    private String apiId;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        String zipBase64 = Base64.getEncoder().encodeToString(minimalZip());
        signedLambdaPost("/2015-03-31/functions", """
                {
                  "FunctionName": "%s",
                  "Runtime": "nodejs20.x",
                  "Role": "%s",
                  "Handler": "index.handler",
                  "Code": { "ZipFile": "%s" }
                }
                """.formatted(FUNCTION, ROLE_ARN, zipBase64));

        apiId = signedApigwPost("/restapis", """
                {"name":"source-arn-permission-api"}""")
                .extract().path("id");

        signedLambdaPost("/2015-03-31/functions/" + FUNCTION + "/policy", """
                {
                  "StatementId": "allow-apigw-source-arn",
                  "Action": "lambda:InvokeFunction",
                  "Principal": "apigateway.amazonaws.com",
                  "SourceArn": "arn:aws:execute-api:%s:%s:%s/*/*/*"
                }
                """.formatted(REGION, ACCOUNT, apiId));

        String rootId = signedApigwGet("/restapis/" + apiId + "/resources")
                .extract().path("item[0].id");

        String resourceId = signedApigwPost("/restapis/" + apiId + "/resources/" + rootId, """
                {"pathPart":"probe"}""")
                .extract().path("id");

        signedApigwPut("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET", """
                {"authorizationType":"NONE"}""");

        String proxyUri = "arn:aws:apigateway:" + REGION + ":lambda:path/2015-03-31/functions/"
                + "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + FUNCTION + "/invocations";
        signedApigwPut("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/integration", """
                {"type":"AWS_PROXY","httpMethod":"POST","uri":"%s"}"""
                .formatted(proxyUri));

        String deploymentId = signedApigwPost("/restapis/" + apiId + "/deployments", """
                {"description":"source-arn-test"}""")
                .extract().path("id");

        signedApigwPost("/restapis/" + apiId + "/stages", """
                {"stageName":"prod","deploymentId":"%s"}""".formatted(deploymentId));
    }

    @Test
    void unsignedUserRequestLambdaProxyPassesSourceArnResourcePolicy() {
        given()
        .when()
                .get("/restapis/" + apiId + "/prod/_user_request_/probe")
        .then()
                .statusCode(200)
                .body(containsString("ok"));
    }

    private static byte[] minimalZip() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("index.js"));
            zos.write("""
                    exports.handler = async () => ({
                      statusCode: 200,
                      body: "ok"
                    });
                    """.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

    private io.restassured.response.ValidatableResponse signedApigwPost(String path, String body) throws Exception {
        return signedJsonPost(path, body, APIGW_SERVICE);
    }

    private io.restassured.response.ValidatableResponse signedLambdaPost(String path, String body) throws Exception {
        return signedJsonPost(path, body, LAMBDA_SERVICE);
    }

    private io.restassured.response.ValidatableResponse signedJsonPost(String path, String body, String service)
            throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                service,
                Instant.now()))
                .body(body)
        .when()
                .post(path)
        .then()
                .statusCode(201);
    }

    private io.restassured.response.ValidatableResponse signedApigwPut(String path, String body) throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                APIGW_SERVICE,
                Instant.now()))
                .body(body)
        .when()
                .put(path)
        .then()
                .statusCode(201);
    }

    private io.restassured.response.ValidatableResponse signedApigwGet(String path) throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestGet(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                APIGW_SERVICE,
                Instant.now()))
        .when()
                .get(path)
        .then()
                .statusCode(200);
    }

    private io.restassured.specification.RequestSpecification applySignedRest(
            SigV4HttpTestSupport.SignedRestHeaders signed) {
        return given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/json");
    }
}
