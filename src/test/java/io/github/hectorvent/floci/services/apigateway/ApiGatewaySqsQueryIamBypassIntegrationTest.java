package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Regression: path-style APIGW query integrations require execution-role IAM.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class ApiGatewaySqsQueryIamBypassIntegrationTest {

    private static final String QUEUE_NAME = "apigw-query-iam-bypass";
    private static final String ROLE_NAME = "ApigwQueryExecRole";
    private static final String ROLE_ARN =
            "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":role/" + ROLE_NAME;

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    AwsServiceRouter serviceRouter;

    private String queueUrl;
    private String rootSqs;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        rootSqs = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "sqs");
        queueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", QUEUE_NAME)
                .header("Authorization", rootSqs)
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString(
                        "CreateQueueResponse.CreateQueueResult.QueueUrl");

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", ROLE_NAME)
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
                .formParam("RoleName", ROLE_NAME)
                .formParam("PolicyName", "AllowSqsSend")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void invokeQueryDeniedWithoutExecutionRole() {
        MultivaluedMap<String, String> params = querySendMessageParams();

        AwsException ex = assertThrows(AwsException.class,
                () -> serviceRouter.invokeQuery("sqs", params, "us-east-1", null));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void invokeQuerySucceedsWithExecutionRole() {
        MultivaluedMap<String, String> params = querySendMessageParams();

        assertEquals(200, serviceRouter.invokeQuery("sqs", params, "us-east-1", ROLE_ARN).getStatus());
    }

    private MultivaluedMap<String, String> querySendMessageParams() {
        MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
        params.add("Action", "SendMessage");
        params.add("QueueUrl", queueUrl);
        params.add("MessageBody", "iam-regression");
        return params;
    }
}
