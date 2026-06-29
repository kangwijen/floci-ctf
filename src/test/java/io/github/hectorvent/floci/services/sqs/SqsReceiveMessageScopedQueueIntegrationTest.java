package io.github.hectorvent.floci.services.sqs;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * {@code sqs:ReceiveMessage} scoped via HTTP {@code QueueUrl} parsing.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SqsReceiveMessageScopedQueueIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String ALLOWED_QUEUE = "allowed-queue";
    private static final String DECOY_QUEUE = "other-queue";

    private String playerAkid;
    private String allowedQueueUrl;
    private String decoyQueueUrl;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sqs-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSqs = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sqs/aws4_request";

        allowedQueueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", ALLOWED_QUEUE)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        decoyQueueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", DECOY_QUEUE)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        given()
                .formParam("Action", "SendMessage")
                .formParam("QueueUrl", allowedQueueUrl)
                .formParam("MessageBody", "site-id=42")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sqs:ReceiveMessage",
               "Resource":"arn:aws:sqs:us-east-1:%s:%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_QUEUE);
        CtfLabIamTestSupport.putUserPolicy(user, "sqs-receive-one", policy);
    }

    @Test
    @Order(1)
    void receiveAllowedQueue() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", allowedQueueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("site-id=42"));
    }

    @Test
    @Order(2)
    void receiveDecoyQueueDenied() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", decoyQueueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    @Order(3)
    void receiveAllowedQueueWithAlternateHostStillScoped() {
        String rootSqs = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "SendMessage")
                .formParam("QueueUrl", allowedQueueUrl)
                .formParam("MessageBody", "site-id=alt-host")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        java.net.URI uri = java.net.URI.create(allowedQueueUrl);
        String altHostUrl = "http://localhost.localstack.cloud:" + uri.getPort() + uri.getPath();
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", altHostUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("site-id=alt-host"));
    }

    @Test
    @Order(4)
    void receiveAllowedQueueViaJsonProtocol() {
        String rootSqs = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "SendMessage")
                .formParam("QueueUrl", allowedQueueUrl)
                .formParam("MessageBody", "site-id=json-protocol")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        com.fasterxml.jackson.databind.node.ObjectNode body = mapper.createObjectNode();
        body.put("QueueUrl", allowedQueueUrl);
        body.put("MaxNumberOfMessages", 1);

        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "AmazonSQS.ReceiveMessage")
                .contentType("application/x-amz-json-1.0")
                .body(body.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("Messages[0].Body", containsString("site-id=json-protocol"));
    }

    @Test
    @Order(5)
    void receiveAllowedQueueViaJsonProtocolAfterAssumeRole() {
        String roleName = "sqs-receive-role";
        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"arn:aws:iam::%s:user/sqs-test-user"},
              "Action":"sts:AssumeRole"
            }]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT);

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", trustPolicy)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        String roleArn = "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":role/" + roleName;
        String rolePolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sqs:ReceiveMessage",
               "Resource":"arn:aws:sqs:us-east-1:%s:%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_QUEUE);
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "sqs-receive-json")
                .formParam("PolicyDocument", rolePolicy)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        String assumePolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"}
            ]}""".formatted(roleArn);
        CtfLabIamTestSupport.putUserPolicy("sqs-test-user", "assume-sqs-role", assumePolicy);

        String rootSqs = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "SendMessage")
                .formParam("QueueUrl", allowedQueueUrl)
                .formParam("MessageBody", "site-id=json-assumed-role")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        String stsAuth = CtfLabIamTestSupport.scopedAuth(playerAkid, "sts");
        String sessionAkid = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "sqs-json")
                .header("Authorization", stsAuth)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");

        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        com.fasterxml.jackson.databind.node.ObjectNode body = mapper.createObjectNode();
        body.put("QueueUrl", allowedQueueUrl);
        body.put("MaxNumberOfMessages", 1);

        String sqsAuth = CtfLabIamTestSupport.scopedAuth(sessionAkid, "sqs");
        given()
                .header("Authorization", sqsAuth)
                .header("X-Amz-Target", "AmazonSQS.ReceiveMessage")
                .contentType("application/x-amz-json-1.0")
                .body(body.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("Messages[0].Body", containsString("site-id=json-assumed-role"));
    }
}
