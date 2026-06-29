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
import static org.hamcrest.Matchers.not;

/**
 * CTF SNS topics omit the upstream default topic policy; publish requires explicit IAM or resource policy.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SnsTopicNoDefaultPolicyIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String TOPIC = "no-default-policy-topic";

    private String playerAkid;
    private String topicArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sns-no-policy-player";
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
    }

    @Test
    void getTopicAttributesOmitsDefaultPolicy() {
        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";

        given()
                .formParam("Action", "GetTopicAttributes")
                .formParam("TopicArn", topicArn)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .body(not(containsString("<key>Policy</key>")));
    }

    @Test
    void publishDeniedWithoutIdentityOrResourcePolicy() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "should-not-publish")
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
