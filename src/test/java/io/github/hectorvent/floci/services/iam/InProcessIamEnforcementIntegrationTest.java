package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.apigateway.AwsServiceRouter;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Verifies IAM enforcement on in-process API Gateway AWS integrations (KMS/Secrets path).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InProcessIamEnforcementIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String SECRET_NAME = "test/inprocess/secret";
    private static final String ROLE_NAME = "InProcessApigwExecRole";
    private static final String ROLE_ARN =
            "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":role/" + ROLE_NAME;

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    AwsServiceRouter serviceRouter;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", ROLE_NAME)
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},
                       "Action":"sts:AssumeRole"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", ROLE_NAME)
                .formParam("PolicyName", "DenySecretsRead")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        ObjectNode create = objectMapper.createObjectNode();
        create.put("Name", SECRET_NAME);
        create.put("SecretString", "inprocess-secret-value");
        given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType("application/x-amz-json-1.1")
                .body(create.toString())
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void enforcementDeniesInProcessCallWithoutExecutionRole() {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("SecretId", SECRET_NAME);

        AwsException ex = assertThrows(AwsException.class,
                () -> serviceRouter.invoke("secretsmanager", "GetSecretValue", body, REGION, null));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void inProcessCallUsesExecutionRolePolicies() {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("SecretId", SECRET_NAME);

        AwsException ex = assertThrows(AwsException.class,
                () -> serviceRouter.invoke("secretsmanager", "GetSecretValue", body, REGION, ROLE_ARN));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void inProcessCallAllowsWhenRoleHasPermission() {
        String allowRole = "InProcessApigwAllowRole";
        String allowRoleArn =
                "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":role/" + allowRole;

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", allowRole)
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},
                       "Action":"sts:AssumeRole"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", allowRole)
                .formParam("PolicyName", "AllowSecretRead")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
                       "Resource":"arn:aws:secretsmanager:%s:%s:secret:%s-*"}
                    ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT, SECRET_NAME))
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        ObjectNode body = objectMapper.createObjectNode();
        body.put("SecretId", SECRET_NAME);

        var response = serviceRouter.invoke("secretsmanager", "GetSecretValue", body, REGION, allowRoleArn);
        assertEquals(200, response.getStatus());
    }
}
