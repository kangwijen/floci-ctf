package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * HTTP integration tests for role trust policy enforcement on {@code sts:AssumeRole}.
 */
@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StsAssumeRoleTrustIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/iam/aws4_request";

    private static String userAccessKeyId;
    private static String roleArn;

    @Test
    @Order(1)
    void provisionUserRoleAndKey() {
        given()
            .formParam("Action", "CreateUser")
            .formParam("UserName", "ext-a")
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);

        userAccessKeyId = given()
            .formParam("Action", "CreateAccessKey")
            .formParam("UserName", "ext-a")
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200)
            .extract().xmlPath()
            .getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");

        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"arn:aws:iam::%s:user/ext-a"},
              "Action":"sts:AssumeRole",
              "Condition":{"StringEquals":{"sts:ExternalId":"need-this"}}
            }]}""".formatted(ACCOUNT);

        given()
            .formParam("Action", "CreateRole")
            .formParam("RoleName", "ext-role")
            .formParam("AssumeRolePolicyDocument", trustPolicy)
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);

        roleArn = "arn:aws:iam::" + ACCOUNT + ":role/ext-role";

        String identityPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"}
            }]}""".formatted(roleArn);

        given()
            .formParam("Action", "PutUserPolicy")
            .formParam("UserName", "ext-a")
            .formParam("PolicyName", "assume-ext-role")
            .formParam("PolicyDocument", identityPolicy)
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);
    }

    @Test
    @Order(2)
    void assumeRoleDeniesWrongExternalId() {
        String stsAuth = "AWS4-HMAC-SHA256 Credential=" + userAccessKeyId
                + "/20260227/us-east-1/sts/aws4_request";

        given()
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", roleArn)
            .formParam("RoleSessionName", "s1")
            .formParam("ExternalId", "WRONG")
            .header("Authorization", stsAuth)
        .when().post("/")
        .then()
            .statusCode(403)
            .body(containsString("AccessDenied"));
    }

    @Test
    @Order(3)
    void assumeRoleAllowsCorrectExternalId() {
        String stsAuth = "AWS4-HMAC-SHA256 Credential=" + userAccessKeyId
                + "/20260227/us-east-1/sts/aws4_request";

        given()
            .formParam("Action", "AssumeRole")
            .formParam("RoleArn", roleArn)
            .formParam("RoleSessionName", "s2")
            .formParam("ExternalId", "need-this")
            .header("Authorization", stsAuth)
        .when().post("/")
        .then()
            .statusCode(200)
            .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }
}
