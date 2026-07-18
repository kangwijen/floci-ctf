package io.github.hectorvent.floci.services.sqs;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * SQS queue policy Principal for a foreign account must not authorize a default-account IAM user.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class SqsForeignPrincipalDenyIntegrationTest {

    private static final String FOREIGN_ACCOUNT = "111122223333";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String queueUrl;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sqs-foreign-principal-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSqs = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "sqs");
        String queueName = "foreign-principal-" + UUID.randomUUID().toString().substring(0, 8);

        queueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", queueName)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        String queueArn = "arn:aws:sqs:us-east-1:" + CtfLabIamEnforcementProfile.ACCOUNT + ":" + queueName;
        String queuePolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow",
                   "Principal":{"AWS":"arn:aws:iam::%s:root"},
                   "Action":"sqs:ReceiveMessage",
                   "Resource":"%s"}
                ]}""".formatted(FOREIGN_ACCOUNT, queueArn);
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
                .formParam("MessageBody", "foreign-principal-payload")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void receiveMessageDeniedWhenQueuePolicyAllowsOnlyForeignAccount() {
        String auth = CtfLabIamTestSupport.scopedAuth(playerAkid, "sqs");
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", queueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
