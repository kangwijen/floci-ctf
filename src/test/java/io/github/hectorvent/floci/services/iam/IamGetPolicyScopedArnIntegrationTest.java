package io.github.hectorvent.floci.services.iam;

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
 * F7: {@code iam:GetPolicy} scoped to one managed policy ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamGetPolicyScopedArnIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;
    private String allowedPolicyArn;
    private String decoyPolicyArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-getpolicy-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        allowedPolicyArn = given()
                .formParam("Action", "CreatePolicy")
                .formParam("PolicyName", "PathfindingPolicy")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreatePolicyResponse.CreatePolicyResult.Policy.Arn");

        decoyPolicyArn = given()
                .formParam("Action", "CreatePolicy")
                .formParam("PolicyName", "DecoyPolicy")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath().getString("CreatePolicyResponse.CreatePolicyResult.Policy.Arn");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:GetPolicyVersion","Resource":"%s"}
            ]}""".formatted(allowedPolicyArn);
        CtfLabIamTestSupport.putUserPolicy(user, "get-one-policy", policy);
    }

    @Test
    void getAllowedPolicyDocument() {
        given()
                .formParam("Action", "GetPolicyVersion")
                .formParam("PolicyArn", allowedPolicyArn)
                .formParam("VersionId", "v1")
                .header("Authorization", CtfLabIamTestSupport.playerIamAuth(playerAkid))
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("s3:GetObject"));
    }

    @Test
    void getDecoyPolicyDenied() {
        given()
                .formParam("Action", "GetPolicyVersion")
                .formParam("PolicyArn", decoyPolicyArn)
                .formParam("VersionId", "v1")
                .header("Authorization", CtfLabIamTestSupport.playerIamAuth(playerAkid))
                .when().post("/")
                .then().statusCode(403);
    }
}
