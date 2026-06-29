package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * New default policy version applies on the next HTTP call (no stale cache).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class CreatePolicyVersionGrantsSecretReadIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    private String playerAkid;
    private String policyArn;
    private static final String SECRET_NAME = "test/policy-delta-secret";

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "policy-delta";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        policyArn = given()
                .formParam("Action", "CreatePolicy")
                .formParam("PolicyName", "DeltaUnlockPolicy")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreatePolicyResponse.CreatePolicyResult.Policy.Arn");

        given()
                .formParam("Action", "AttachUserPolicy")
                .formParam("UserName", user)
                .formParam("PolicyArn", policyArn)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        String rootSm = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/secretsmanager/aws4_request";
        ObjectNode create = objectMapper.createObjectNode();
        create.put("Name", SECRET_NAME);
        create.put("SecretString", "policy-delta-value");
        given()
                .header("Authorization", rootSm)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType("application/x-amz-json-1.1")
                .body(create.toString())
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    @Order(1)
    void getSecretDeniedBeforePolicyVersion() throws Exception {
        getSecretAsPlayer().statusCode(403);
    }

    @Test
    @Order(2)
    void createPolicyVersionUnlocksSecretRead() throws Exception {
        String unlocked = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":["sts:GetCallerIdentity","secretsmanager:GetSecretValue"],
               "Resource":"*"}
            ]}""";
        given()
                .formParam("Action", "CreatePolicyVersion")
                .formParam("PolicyArn", policyArn)
                .formParam("PolicyDocument", unlocked)
                .formParam("SetAsDefault", "true")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        getSecretAsPlayer()
                .statusCode(200)
                .body("SecretString", equalTo("policy-delta-value"));
    }

    private io.restassured.response.ValidatableResponse getSecretAsPlayer() throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("SecretId", SECRET_NAME);
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid
                + "/20260227/us-east-1/secretsmanager/aws4_request";
        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then();
    }
}
