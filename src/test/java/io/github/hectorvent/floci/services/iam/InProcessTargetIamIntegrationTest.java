package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.AwsException;
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * IAM enforcement on non-HTTP asynchronous delivery paths (pipes, scheduler, EventBridge, SNS).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InProcessTargetIamIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String QUEUE_ARN =
            "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":ctf-inprocess-pipe-target";
    private static final String DENY_ROLE = "InProcessPipeDenyRole";
    private static final String DENY_ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/" + DENY_ROLE;
    private static final String ALLOW_ROLE = "InProcessPipeAllowRole";
    private static final String ALLOW_ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/" + ALLOW_ROLE;

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    InProcessTargetAuthorizer targetAuthorizer;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", DENY_ROLE)
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"Service":"pipes.amazonaws.com"},
                       "Action":"sts:AssumeRole"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", DENY_ROLE)
                .formParam("PolicyName", "DenySqsSend")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Deny","Action":"sqs:SendMessage","Resource":"*"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", ALLOW_ROLE)
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"Service":"pipes.amazonaws.com"},
                       "Action":"sts:AssumeRole"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", ALLOW_ROLE)
                .formParam("PolicyName", "AllowSqsSend")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"sqs:SendMessage",
                       "Resource":"arn:aws:sqs:%s:%s:ctf-inprocess-pipe-target"}
                    ]}""".formatted(REGION, ACCOUNT))
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void pipeTargetDeniesWhenExecutionRoleLacksPermission() {
        AwsException ex = assertThrows(AwsException.class,
                () -> targetAuthorizer.authorizePipeTarget(DENY_ROLE_ARN, QUEUE_ARN, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void pipeTargetAllowsWhenExecutionRoleHasScopedPermission() {
        assertDoesNotThrow(() -> targetAuthorizer.authorizePipeTarget(ALLOW_ROLE_ARN, QUEUE_ARN, REGION));
    }

    @Test
    void pipeTargetDeniesMissingExecutionRole() {
        AwsException ex = assertThrows(AwsException.class,
                () -> targetAuthorizer.authorizePipeTarget(null, QUEUE_ARN, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void eventBridgeTargetDeniesWithoutResourcePolicyOrRole() {
        String lambdaArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:ctf-eb-no-policy";
        AwsException ex = assertThrows(AwsException.class,
                () -> targetAuthorizer.authorizeEventBridgeTarget(null, lambdaArn, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }
}
