package io.github.hectorvent.floci.services.cloudformation;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * F6: {@code cloudformation:DescribeStacks} scoped to one stack name.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloudFormationDescribeStacksScopedIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String LAB_STACK = "ctf-lab-stack";
    private static final String DECOY_STACK = "ctf-decoy-stack";
    private static final String TEMPLATE = """
            {"AWSTemplateFormatVersion":"2010-09-09",
             "Resources":{},
             "Outputs":{"SecretName":{"Value":"ctf/witness-secret"},
                        "KmsKeyId":{"Value":"alias/ctf-lab-key"}}}""";

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-cfn-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootCfn = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/cloudformation/aws4_request";

        createStack(rootCfn, LAB_STACK);
        createStack(rootCfn, DECOY_STACK);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"cloudformation:DescribeStacks",
               "Resource":"arn:aws:cloudformation:us-east-1:%s:stack/%s/*"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, LAB_STACK);
        CtfLabIamTestSupport.putUserPolicy(user, "cfn-describe-one", policy);
    }

    private static void createStack(String auth, String stackName) {
        given()
                .formParam("Action", "CreateStack")
                .formParam("StackName", stackName)
                .formParam("TemplateBody", TEMPLATE)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void describeAllowedStackReturnsOutputs() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid
                + "/20260227/us-east-1/cloudformation/aws4_request";
        given()
                .formParam("Action", "DescribeStacks")
                .formParam("StackName", LAB_STACK)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("ctf/witness-secret"))
                .body(containsString("alias/ctf-lab-key"));
    }

    @Test
    void describeDecoyStackDenied() {
        String auth = "AWS4-HMAC-SHA256 Credential=" + playerAkid
                + "/20260227/us-east-1/cloudformation/aws4_request";
        given()
                .formParam("Action", "DescribeStacks")
                .formParam("StackName", DECOY_STACK)
                .header("Authorization", auth)
                .when().post("/")
                .then().statusCode(403);
    }
}
