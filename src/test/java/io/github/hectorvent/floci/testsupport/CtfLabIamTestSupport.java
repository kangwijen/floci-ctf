package io.github.hectorvent.floci.testsupport;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.restassured.RestAssured;

import java.net.URL;

import static io.restassured.RestAssured.given;

/**
 * Shared IAM provisioning helpers for CTF lab integration tests.
 */
public final class CtfLabIamTestSupport {

    private CtfLabIamTestSupport() {}

    /** Binds RestAssured to the Quarkus test HTTP endpoint (required with {@code @TestProfile}). */
    public static void bindRestAssured(URL endpoint) {
        RestAssuredJsonUtils.configureAwsContentTypes();
        RestAssured.baseURI = endpoint.toString();
        RestAssured.port = endpoint.getPort();
    }

    public static String createUser(String userName) {
        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", userName)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
        return userName;
    }

    public static String createAccessKey(String userName) {
        return given()
                .formParam("Action", "CreateAccessKey")
                .formParam("UserName", userName)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
    }

    public static void putUserPolicy(String userName, String policyName, String policyDocument) {
        given()
                .formParam("Action", "PutUserPolicy")
                .formParam("UserName", userName)
                .formParam("PolicyName", policyName)
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
    }

    public static String playerAuth(String accessKeyId) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/s3/aws4_request";
    }

    public static String playerIamAuth(String accessKeyId) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/iam/aws4_request";
    }

    public static String playerStsAuth(String accessKeyId) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/sts/aws4_request";
    }

    public static String scopedAuth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/" + service + "/aws4_request";
    }
}
