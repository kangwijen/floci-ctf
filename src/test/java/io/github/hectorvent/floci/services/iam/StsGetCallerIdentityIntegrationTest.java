package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URL;

import static io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile.ACCOUNT;
import static io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile.AUTH;
import static io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.startsWith;

/**
 * CTF {@code sts:GetCallerIdentity} identity fidelity under IAM enforcement.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StsGetCallerIdentityIntegrationTest {

    private static final String USER = "gci-player";
    private static final String ROLE_NAME = "gci-assumed-role";
    private static final String SESSION_NAME = "gci-session";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAccessKeyId;
    private String roleArn;
    private String assumedRoleArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        CtfLabIamTestSupport.createUser(USER);
        playerAccessKeyId = CtfLabIamTestSupport.createAccessKey(USER);

        String userArn = "arn:aws:iam::" + ACCOUNT + ":user/" + USER;
        roleArn = "arn:aws:iam::" + ACCOUNT + ":role/" + ROLE_NAME;
        assumedRoleArn = "arn:aws:sts::" + ACCOUNT + ":assumed-role/" + ROLE_NAME + "/" + SESSION_NAME;

        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"%s"},
              "Action":"sts:AssumeRole"
            }]}""".formatted(userArn);

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", ROLE_NAME)
                .formParam("AssumeRolePolicyDocument", trustPolicy)
                .header("Authorization", AUTH)
                .when().post("/")
                .then().statusCode(200);

        String identityPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"}
            ]}""".formatted(roleArn);
        CtfLabIamTestSupport.putUserPolicy(USER, "assume-gci-role", identityPolicy);
    }

    @Test
    @Order(1)
    void iamUserGetCallerIdentityReturnsUserArnNotRoot() {
        String expectedArn = "arn:aws:iam::" + ACCOUNT + ":user/" + USER;

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(playerAccessKeyId))
                .when().post("/")
                .then()
                .statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Account", equalTo(ACCOUNT))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", equalTo(expectedArn))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", not(containsString(":root")));
    }

    @Test
    @Order(2)
    void assumedRoleGetCallerIdentityReturnsAssumedRoleArn() {
        String tempAccessKeyId = given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", SESSION_NAME)
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(playerAccessKeyId))
                .when().post("/")
                .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .body("AssumeRoleResponse.AssumeRoleResult.AssumedRoleUser.Arn", equalTo(assumedRoleArn))
                .extract().xmlPath()
                .getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(tempAccessKeyId))
                .when().post("/")
                .then()
                .statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Account", equalTo(ACCOUNT))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", equalTo(assumedRoleArn))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", not(containsString(":root")));
    }

    @Test
    @Order(3)
    void operatorRootGetCallerIdentityReturnsConfiguredRootPrincipal() {
        String rootArn = "arn:aws:iam::" + ACCOUNT + ":root";
        String rootStsAuth = "AWS4-HMAC-SHA256 Credential=" + ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/sts/aws4_request";

        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", rootStsAuth)
                .when().post("/")
                .then()
                .statusCode(200)
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Account", equalTo(ACCOUNT))
                .body("GetCallerIdentityResponse.GetCallerIdentityResult.Arn", equalTo(rootArn));
    }

}
