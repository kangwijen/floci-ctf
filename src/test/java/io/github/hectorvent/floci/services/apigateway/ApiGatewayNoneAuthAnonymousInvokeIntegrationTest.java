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

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * API Gateway {@code authorizationType=NONE} allows unsigned {@code _user_request_} invoke
 * under IAM strict enforcement via {@link io.github.hectorvent.floci.core.common.AnonymousAccessGate}.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiGatewayNoneAuthAnonymousInvokeIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String SERVICE = "apigateway";

    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;
    private String apiId;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        apiId = signedJsonPost("/restapis", """
                {"name":"anonymous-none-auth-api"}""")
                .extract().path("id");

        String rootId = signedJsonGet("/restapis/" + apiId + "/resources")
                .extract().path("item[0].id");

        String resourceId = signedJsonPost("/restapis/" + apiId + "/resources/" + rootId, """
                {"pathPart":"probe"}""")
                .extract().path("id");

        signedJsonPut("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET", """
                {"authorizationType":"NONE"}""");

        signedJsonPut("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/responses/200", """
                {"responseParameters":{}}""");

        signedJsonPut("/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/integration", """
                {"type":"MOCK","requestTemplates":{"application/json":"{\\"statusCode\\": 200}"}}""");

        signedJsonPut(
                "/restapis/" + apiId + "/resources/" + resourceId + "/methods/GET/integration/responses/200",
                """
                {"selectionPattern":"","responseTemplates":{"application/json":"{\\"ok\\":true}"}}""");

        String deploymentId = signedJsonPost("/restapis/" + apiId + "/deployments", """
                {"description":"anonymous-test"}""")
                .extract().path("id");

        signedJsonPost("/restapis/" + apiId + "/stages", """
                {"stageName":"prod","deploymentId":"%s"}""".formatted(deploymentId));
    }

    @Test
    void unsignedUserRequestInvokeSucceedsWithAuthorizationTypeNone() {
        given()
        .when()
                .get("/restapis/" + apiId + "/prod/_user_request_/probe")
        .then()
                .statusCode(200)
                .body(containsString("\"ok\":true"));
    }

    private io.restassured.response.ValidatableResponse signedJsonPost(String path, String body) throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                SERVICE,
                Instant.now()))
                .body(body)
        .when()
                .post(path)
        .then()
                .statusCode(201);
    }

    private io.restassured.response.ValidatableResponse signedJsonPut(String path, String body) throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                SERVICE,
                Instant.now()))
                .body(body)
        .when()
                .put(path)
        .then();
    }

    private io.restassured.response.ValidatableResponse signedJsonGet(String path) throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestGet(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                SERVICE,
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
