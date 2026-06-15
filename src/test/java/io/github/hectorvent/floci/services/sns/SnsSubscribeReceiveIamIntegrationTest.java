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
 * {@code sns:Subscribe} scoped to one topic ARN; fan-out to SQS without participant {@code sns:Publish}.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SnsSubscribeReceiveIamIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String TOPIC = "dispatch-topic";
    private static final String DECOY_TOPIC = "decoy-topic";
    private static final String QUEUE = "dispatch-queue";

    private String playerAkid;
    private String topicArn;
    private String decoyTopicArn;
    private String queueUrl;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "sns-test-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";
        String rootSqs = rootSns.replace("/sns/", "/sqs/");

        topicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", TOPIC)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        decoyTopicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", DECOY_TOPIC)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        queueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", QUEUE)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        String queueArn = "arn:aws:sqs:us-east-1:" + CtfLabIamEnforcementProfile.ACCOUNT + ":" + QUEUE;
        String queuePolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                + "\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"sqs:SendMessage\","
                + "\"Resource\":\"" + queueArn + "\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\""
                + topicArn + "\"}}}]}";
        given()
                .formParam("Action", "SetQueueAttributes")
                .formParam("QueueUrl", queueUrl)
                .formParam("Attribute.1.Name", "Policy")
                .formParam("Attribute.1.Value", queuePolicy)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":["sns:Subscribe","sqs:ReceiveMessage"],
               "Resource":["%s","arn:aws:sqs:us-east-1:%s:%s"]}
            ]}""".formatted(topicArn, CtfLabIamEnforcementProfile.ACCOUNT, QUEUE);
        CtfLabIamTestSupport.putUserPolicy(user, "sns-dispatch", policy);
    }

    @Test
    void subscribeAllowedTopic() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Subscribe")
                .formParam("TopicArn", topicArn)
                .formParam("Protocol", "sqs")
                .formParam("Endpoint", queueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void subscribeDecoyTopicDeniedWithoutResourcePolicy() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Subscribe")
                .formParam("TopicArn", decoyTopicArn)
                .formParam("Protocol", "sqs")
                .formParam("Endpoint", queueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    void confirmSubscriptionDeniedWithoutConfirmPermission() {
        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";
        String httpTopicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", "http-confirm-topic")
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        String subscribeOnlyPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sns:Subscribe","Resource":"%s"}
            ]}""".formatted(httpTopicArn);
        CtfLabIamTestSupport.putUserPolicy("sns-test-player", "sns-subscribe-only", subscribeOnlyPolicy);

        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "ConfirmSubscription")
                .formParam("TopicArn", httpTopicArn)
                .formParam("Token", "not-a-real-token")
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    void operatorPublishFanOutReadableWithoutPlayerPublish() {
        subscribeAllowedTopic();

        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "routing=west-terminal")
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200);

        String sqsAuth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", queueUrl)
                .header("Authorization", sqsAuth)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("routing=west-terminal"));
    }

    @Test
    void fanOutWithExplicitTopicAndQueueResourcePolicies() {
        String rootSns = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sns/aws4_request";
        String rootSqs = rootSns.replace("/sns/", "/sqs/");

        String policyTopicArn = given()
                .formParam("Action", "CreateTopic")
                .formParam("Name", "policy-fanout-topic")
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateTopicResponse.CreateTopicResult.TopicArn");

        String policyQueueUrl = given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", "policy-fanout-queue")
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreateQueueResponse.CreateQueueResult.QueueUrl");

        String policyQueueArn = "arn:aws:sqs:us-east-1:" + CtfLabIamEnforcementProfile.ACCOUNT
                + ":policy-fanout-queue";
        String queuePolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                + "\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"sqs:SendMessage\","
                + "\"Resource\":\"" + policyQueueArn + "\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\""
                + policyTopicArn + "\"}}}]}";
        given()
                .formParam("Action", "SetQueueAttributes")
                .formParam("QueueUrl", policyQueueUrl)
                .formParam("Attribute.1.Name", "Policy")
                .formParam("Attribute.1.Value", queuePolicy)
                .header("Authorization", rootSqs)
                .when().post("/")
                .then().statusCode(200);

        String topicPolicy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\","
                + "\"Principal\":{\"AWS\":\"arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT
                + ":root\"},\"Action\":\"sns:Publish\",\"Resource\":\"" + policyTopicArn + "\"}]}";
        given()
                .formParam("Action", "SetTopicAttributes")
                .formParam("TopicArn", policyTopicArn)
                .formParam("AttributeName", "Policy")
                .formParam("AttributeValue", topicPolicy)
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200);

        String playerPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":["sns:Subscribe","sqs:ReceiveMessage"],
               "Resource":["%s","%s"]}
            ]}""".formatted(policyTopicArn, policyQueueArn);
        CtfLabIamTestSupport.putUserPolicy("sns-test-player", "policy-fanout", playerPolicy);

        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Subscribe")
                .formParam("TopicArn", policyTopicArn)
                .formParam("Protocol", "sqs")
                .formParam("Endpoint", policyQueueUrl)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200);

        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", policyTopicArn)
                .formParam("Message", "policy-fanout=payload")
                .header("Authorization", rootSns)
                .when().post("/")
                .then().statusCode(200);

        String sqsAuth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sqs/aws4_request";
        given()
                .formParam("Action", "ReceiveMessage")
                .formParam("QueueUrl", policyQueueUrl)
                .header("Authorization", sqsAuth)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("policy-fanout=payload"));
    }

    @Test
    void playerPublishDeniedWithoutSnsPublishPermission() {
        subscribeAllowedTopic();

        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/sns/aws4_request";
        given()
                .formParam("Action", "Publish")
                .formParam("TopicArn", topicArn)
                .formParam("Message", "player-should-not-publish")
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
