package io.github.hectorvent.floci.services.apigatewayv2.websocket;

import io.github.hectorvent.floci.services.apigatewayv2.WebSocketTestSupport;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * WebSocket {@code $connect} bypasses JAX-RS entirely (registered directly on the Vert.x
 * {@code Router}, see {@link WebSocketHandler#init}), so neither {@code SigV4ValidationFilter}
 * nor {@code IamEnforcementFilter} ever inspect it. Before {@link WebSocketHandler#authorizeConnect}
 * existed, any caller could open a WebSocket connection to any API regardless of IAM policy or
 * signature validity. These tests confirm the upgrade is now gated by
 * {@code execute-api:Invoke} the same way the HTTP execute-api path is gated.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WebSocketConnectIamGateIntegrationTest {

    @TestHTTPResource("/")
    URI baseUri;

    private static String apiId;
    private static String routeArn;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(baseUri.toURL());

        apiId = given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .contentType(ContentType.JSON)
                .body("""
                        {"name":"ws-iam-gate-test","protocolType":"WEBSOCKET",
                         "routeSelectionExpression":"$request.body.action"}""")
                .when().post("/v2/apis")
                .then()
                .statusCode(201)
                .body("apiId", notNullValue())
                .extract().path("apiId");

        given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .contentType(ContentType.JSON)
                .body("""
                        {"stageName":"test"}""")
                .when().post("/v2/apis/" + apiId + "/stages")
                .then()
                .statusCode(201);

        // No $connect route is registered, so an authorized caller completes the upgrade
        // directly (WebSocketHandler#completeUpgrade) without needing a Lambda integration.
        routeArn = "arn:aws:execute-api:us-east-1:" + CtfLabIamEnforcementProfile.ACCOUNT
                + ":" + apiId + "/test/$connect";
    }

    private String createPlayerAuth(String userName, String policyDocument) {
        CtfLabIamTestSupport.createUser(userName);
        String akid = CtfLabIamTestSupport.createAccessKey(userName);
        if (policyDocument != null) {
            CtfLabIamTestSupport.putUserPolicy(userName, userName + "-policy", policyDocument);
        }
        return CtfLabIamTestSupport.scopedAuth(akid, "execute-api");
    }

    private void assertConnectFails(String authHeader, int expectedStatus) throws Exception {
        String wsUrl = WebSocketTestSupport.buildWsUrl(baseUri, apiId, "test");
        HttpClient client = HttpClient.newHttpClient();
        WebSocket.Builder builder = client.newWebSocketBuilder();
        if (authHeader != null) {
            builder.header("Authorization", authHeader);
        }
        CompletableFuture<WebSocket> wsFuture = builder.buildAsync(URI.create(wsUrl), new WebSocket.Listener() {});

        try {
            wsFuture.get(30, TimeUnit.SECONDS);
            fail("Expected WebSocket connection to fail with status " + expectedStatus);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            assertNotNull(cause, "Expected a cause for the ExecutionException");
            // The JDK WebSocket client wraps the rejected handshake as a WebSocketHandshakeException
            // whose cause is a CheckFailedException carrying the actual HTTP status code.
            String message = cause.getMessage() != null ? cause.getMessage() : "";
            Throwable walk = cause;
            while (!message.contains(String.valueOf(expectedStatus)) && walk.getCause() != null) {
                walk = walk.getCause();
                message = walk.getMessage() != null ? walk.getMessage() : message;
            }
            assertTrue(message.contains(String.valueOf(expectedStatus)),
                    "Expected connection failure with status " + expectedStatus + " but got: " + cause);
        }
    }

    @Test
    void connectRejectedWithoutAuthorizationHeader() throws Exception {
        assertConnectFails(null, 403);
    }

    @Test
    void connectRejectedWhenCallerLacksExecuteApiInvokePermission() throws Exception {
        String auth = createPlayerAuth("ws-gate-no-perm", null);
        assertConnectFails(auth, 403);
    }

    @Test
    void connectAllowedWhenCallerHasExecuteApiInvokePermission() throws Exception {
        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"execute-api:Invoke","Resource":"%s"}
                ]}""".formatted(routeArn);
        String auth = createPlayerAuth("ws-gate-allowed", policy);

        String wsUrl = WebSocketTestSupport.buildWsUrl(baseUri, apiId, "test");
        HttpClient client = HttpClient.newHttpClient();
        WebSocket ws = client.newWebSocketBuilder()
                .header("Authorization", auth)
                .buildAsync(URI.create(wsUrl), new WebSocket.Listener() {})
                .get(30, TimeUnit.SECONDS);

        assertNotNull(ws);
        ws.sendClose(WebSocket.NORMAL_CLOSURE, "done");
    }

    @Test
    void connectRejectedWhenCallerHasPermissionOnlyForDifferentRoute() throws Exception {
        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"execute-api:Invoke",
                   "Resource":"arn:aws:execute-api:us-east-1:%s:%s/test/$default"}
                ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, apiId);
        String auth = createPlayerAuth("ws-gate-wrong-route", policy);

        assertConnectFails(auth, 403);
    }
}
