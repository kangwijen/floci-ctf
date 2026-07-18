package io.github.hectorvent.floci.services.sns;

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
 * SNS topic policy Principal for a foreign account must not authorize a default-account IAM user.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class SnsForeignPrincipalDenyIntegrationTest {

    private static final String FOREIGN_ACCOUNT = "111122223333";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String topicArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sns-foreign-principal-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSns = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "sns");
        String topicName = "foreign-principal-" + UUID.randomUUID().toString().substring(0, 8);

        topicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", topicName)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        String topicPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                + "\"Principal\":{\"AWS\":\"arn:aws:iam::" + FOREIGN_ACCOUNT + ":root\"},"
                + "\"Action\":\"sns:Publish\",\"Resource\":\"" + topicArn + "\"}]}";
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
    void publishDeniedWhenTopicPolicyAllowsOnlyForeignAccount() {
        String auth = CtfLabIamTestSupport.scopedAuth(playerAkid, "sns");
        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "foreign-principal-should-deny-local-user")
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
