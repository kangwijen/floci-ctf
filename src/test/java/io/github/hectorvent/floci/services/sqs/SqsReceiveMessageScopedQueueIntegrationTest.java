package io.github.hectorvent.floci.services.sqs;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * F4: {@code sqs:ReceiveMessage} scoped via HTTP {@code QueueUrl} parsing.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SqsReceiveMessageScopedQueueIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String ALLOWED_QUEUE = "ctf-lab-allowed-queue";
    private static final String DECOY_QUEUE = "ctf-lab-decoy-queue";

    private String playerAkid;
    private String allowedQueueUrl;
    private String decoyQueueUrl;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-sqs-player";
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
    void receiveDecoyQueueDenied() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", decoyQueueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403);
    }
}
