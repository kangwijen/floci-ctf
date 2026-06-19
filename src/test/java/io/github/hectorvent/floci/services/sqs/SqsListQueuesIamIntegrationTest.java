package io.github.hectorvent.floci.services.sqs;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * {@code sqs:ListQueues} IAM enforcement returns Query-protocol {@code AccessDenied},
 * not {@code ServiceNotAvailableException}, when the caller lacks permission.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SqsListQueuesIamIntegrationTest {

    private static final String QUEUE_NAME = "ctf-lab-list-queue";
    private static final String REGION = "us-east-1";

    @TestHTTPResource("/")
    URL endpoint;

    private String allowedPlayerAkid;
    private String deniedPlayerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        String rootSqs = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "sqs");

        given()
                .formParam("Action", "CreateQueue")
                .formParam("QueueName", QUEUE_NAME)
                .header("Authorization", rootSqs)
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then().statusCode(200);

        String allowedUser = "ctf-sqs-list-allowed";
        CtfLabIamTestSupport.createUser(allowedUser);
        allowedPlayerAkid = CtfLabIamTestSupport.createAccessKey(allowedUser);
        String allowListPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sqs:ListQueues",
               "Resource":"arn:aws:sqs:%s:%s:*"}
            ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(allowedUser, "sqs-list", allowListPolicy);

        String deniedUser = "ctf-sqs-list-denied";
        CtfLabIamTestSupport.createUser(deniedUser);
        deniedPlayerAkid = CtfLabIamTestSupport.createAccessKey(deniedUser);
        String receiveOnlyPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sqs:ReceiveMessage",
               "Resource":"arn:aws:sqs:%s:%s:%s"}
            ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT, QUEUE_NAME);
        CtfLabIamTestSupport.putUserPolicy(deniedUser, "sqs-receive-only", receiveOnlyPolicy);
    }

    @Test
    void listQueuesAllowedWithWildcardResource() {
        given()
                .formParam("Action", "ListQueues")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(allowedPlayerAkid, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then()
                .statusCode(200)
                .body(containsString(QUEUE_NAME));
    }

    @Test
    void listQueuesDeniedReturnsAccessDeniedNotServiceNotAvailable() {
        given()
                .formParam("Action", "ListQueues")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(deniedPlayerAkid, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(not(containsString("ServiceNotAvailableException")));
    }

    @Test
    void listQueuesImplicitDenyReturnsAccessDeniedNotServiceNotAvailable() {
        String user = "ctf-sqs-list-no-policy";
        CtfLabIamTestSupport.createUser(user);
        String akid = CtfLabIamTestSupport.createAccessKey(user);

        given()
                .formParam("Action", "ListQueues")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(akid, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(not(containsString("ServiceNotAvailableException")));
    }

    @Test
    void listQueuesJsonDeniedReturnsAccessDeniedNotServiceNotAvailable() {
        given()
                .contentType("application/x-amz-json-1.0")
                .header("X-Amz-Target", "AmazonSQS.ListQueues")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(deniedPlayerAkid, "sqs"))
                .body("{}")
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"))
                .body(containsString("sqs:ListQueues"))
                .body(not(containsString("ServiceNotAvailableException")));
    }
}
