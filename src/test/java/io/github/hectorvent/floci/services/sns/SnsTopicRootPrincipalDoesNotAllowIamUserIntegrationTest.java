package io.github.hectorvent.floci.services.sns;

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
 * Account {@code :root} in an SNS topic resource policy does not authorize IAM users without identity policy.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String TOPIC = "root-principal-topic";

    private String playerAkid;
    private String topicArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sns-root-principal-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";

        topicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", TOPIC)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        String topicPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                + "\"Principal\":{\"AWS\":\"arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT
                + ":root\"},\"Action\":\"sns:Publish\",\"Resource\":\"" + topicArn + "\"}]}";
        given()
                .formParam("Action", "SetTopicAttributes")
                .formParam("TopicArn", topicArn)
                .formParam("AttributeName", "Policy")
                .formParam("AttributeValue", topicPolicy)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void iamUserPublishDeniedDespiteRootPrincipalOnTopicPolicy() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "root-principal-should-not-authorize-iam-user")
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
