package io.github.hectorvent.floci.services.cognito;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * Cognito OAuth routes use client credentials / Bearer JWT (not SigV4). Under CTF IAM
 * enforcement they must not bypass policy checks on other services.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CognitoOAuthIamEnforcementIntegrationTest {

    private static final String COGNITO_CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String ROOT_COGNITO_AUTH =
            "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                    + "/20260227/us-east-1/cognito-idp/aws4_request";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String poolId;
    private String confidentialClientId;
    private String confidentialClientSecret;
    private String oauthAccessToken;

    @BeforeAll
    void provisionPoolAndClient() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        JsonNode poolResponse = cognitoJson("CreateUserPool", """
                {
                  "PoolName": "OAuthIamEnforcementPool"
                }
                """);
        poolId = poolResponse.path("UserPool").path("Id").asText();

        cognitoJson("CreateResourceServer", """
                {
                  "UserPoolId": "%s",
                  "Identifier": "notes",
                  "Name": "Notes",
                  "Scopes": [
                    { "ScopeName": "read", "ScopeDescription": "Read" }
                  ]
                }
                """.formatted(poolId));

        JsonNode clientResponse = cognitoJson("CreateUserPoolClient", """
                {
                  "UserPoolId": "%s",
                  "ClientName": "iam-enforcement-oauth-client",
                  "GenerateSecret": true,
                  "AllowedOAuthFlowsUserPoolClient": true,
                  "AllowedOAuthFlows": ["client_credentials"],
                  "AllowedOAuthScopes": ["notes/read"]
                }
                """.formatted(poolId));
        confidentialClientId = clientResponse.path("UserPoolClient").path("ClientId").asText();
        confidentialClientSecret = clientResponse.path("UserPoolClient").path("ClientSecret").asText();

        String basic = Base64.getEncoder()
                .encodeToString((confidentialClientId + ":" + confidentialClientSecret)
                        .getBytes(StandardCharsets.UTF_8));
        oauthAccessToken = given()
                .header("Authorization", "Basic " + basic)
                .formParam("grant_type", "client_credentials")
                .when().post("/cognito-idp/oauth2/token")
                .then().statusCode(200)
                .extract().jsonPath().getString("access_token");
    }

    @Test
    void tokenEndpointWithoutCredentialsRejectedByController() {
        given()
                .formParam("grant_type", "client_credentials")
                .when().post("/cognito-idp/oauth2/token")
                .then()
                .statusCode(400)
                .body("error", equalTo("invalid_request"));
    }

    @Test
    void tokenEndpointAllowsClientSecretPostUnderIamEnforcement() {
        given()
                .formParam("grant_type", "client_credentials")
                .formParam("client_id", confidentialClientId)
                .formParam("client_secret", confidentialClientSecret)
                .when().post("/cognito-idp/oauth2/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"));
    }

    @Test
    void tokenEndpointWithValidBasicAuthSucceeds() {
        String basic = Base64.getEncoder()
                .encodeToString((confidentialClientId + ":" + confidentialClientSecret)
                        .getBytes(StandardCharsets.UTF_8));

        given()
                .header("Authorization", "Basic " + basic)
                .formParam("grant_type", "client_credentials")
                .when().post("/cognito-idp/oauth2/token")
                .then()
                .statusCode(200)
                .body("token_type", equalTo("Bearer"));
    }

    @Test
    void cognitoBearerTokenDoesNotBypassIamOnDataPlane() {
        given()
                .formParam("Action", "ListUsers")
                .header("Authorization", "Bearer " + oauthAccessToken)
                .when().post("/")
                .then()
                .statusCode(403);
    }

    @Test
    void cognitoBearerTokenDoesNotBypassIamOnS3() {
        String bucket = "oauth-iam-enforcement-bucket";
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3"))
                .when().put("/" + bucket)
                .then()
                .statusCode(200);

        given()
                .header("Authorization", "Bearer " + oauthAccessToken)
                .when().get("/" + bucket)
                .then()
                .statusCode(403);
    }

    @Test
    void userInfoWithoutAuthDeniedUnderStrictEnforcement() {
        given()
                .when().get("/cognito-idp/oauth2/userInfo")
                .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private JsonNode cognitoJson(String action, String body) throws Exception {
        String response = given()
                .header("X-Amz-Target", "AWSCognitoIdentityProviderService." + action)
                .header("Authorization", ROOT_COGNITO_AUTH)
                .contentType(COGNITO_CONTENT_TYPE)
                .body(body)
                .when().post("/")
                .then().statusCode(200)
                .extract().asString();
        return OBJECT_MAPPER.readTree(response);
    }
}
