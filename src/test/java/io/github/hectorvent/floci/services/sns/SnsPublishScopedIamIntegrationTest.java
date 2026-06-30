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
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code sns:Publish} scoped to one topic ARN via identity policy.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SnsPublishScopedIamIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String ALLOWED_TOPIC = "allowed-publish-topic";
    private static final String DECOY_TOPIC = "decoy-publish-topic";

    private String playerAkid;
    private String allowedTopicArn;
    private String decoyTopicArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sns-publish-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";

        allowedTopicArn = createTopic(rootSns, ALLOWED_TOPIC);
        decoyTopicArn = createTopic(rootSns, DECOY_TOPIC);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sns:Publish",
               "Resource":"%s"}
            ]}""".formatted(allowedTopicArn);
        CtfLabIamTestSupport.putUserPolicy(user, "sns-publish-one", policy);
    }

    @Test
    void publishAllowedTopic() {
        publish(playerAuth(), allowedTopicArn)
                .statusCode(200);
    }

    @Test
    void publishDecoyTopicDenied() {
        publish(playerAuth(), decoyTopicArn)
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"));
    }

    @Test
    void publishJsonDecoyTopicDenied() {
        String jsonAuth = playerAuth();
        given()
                .header("Authorization", jsonAuth)
                .header("X-Amz-Target", "SNS_20100331.Publish")
                .contentType("application/x-amz-json-1.0")
                .body("""
                        {"TopicArn":"%s","Message":"json-denied"}
                        """.formatted(decoyTopicArn))
                .when().post("/")
                .then().statusCode(403)
                .body(containsString("AccessDenied"));
    }

    private static String createTopic(String rootSns, String name) {
        return given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", name)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");
    }

    private static io.restassured.response.ValidatableResponse publish(String auth, String topicArn) {
        return given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "scoped-publish-test")
                .header("Authorization", auth)
                .when().post("/")
                .then();
    }

    private String playerAuth() {
        return "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
    }
}
