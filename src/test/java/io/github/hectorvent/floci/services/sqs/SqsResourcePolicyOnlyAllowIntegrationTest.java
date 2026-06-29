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
 * {@code sqs:ReceiveMessage} allowed by queue resource policy alone (no identity policy).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SqsResourcePolicyOnlyAllowIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String QUEUE = "resource-policy-queue";

    private String playerAkid;
    private String queueUrl;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sqs-resource-policy-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSqs = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "sqs");

        queueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", QUEUE)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        String queueArn = "arn:aws:sqs:us-east-1:" + CtfLabIamEnforcementProfile.ACCOUNT + ":" + QUEUE;
        String userArn = "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":user/" + user;
        String queuePolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"%s"},
               "Action":"sqs:ReceiveMessage",
               "Resource":"%s"}
            ]}""".formatted(userArn, queueArn);
        given()
                .formParam("Action", "SetQueueAttributes")
                .formParam("QueueUrl", queueUrl)
                .formParam("Attribute.1.Name", "Policy")
                .formParam("Attribute.1.Value", queuePolicy)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "SendMessage")
                .formParam("QueueUrl", queueUrl)
                .formParam("MessageBody", "resource-policy-only")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void receiveMessageSucceedsWithResourcePolicyOnly() {
        String auth = CtfLabIamTestSupport.scopedAuth(playerAkid, "sqs");
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", queueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("resource-policy-only"));
    }
}
