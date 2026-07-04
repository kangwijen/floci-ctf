package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

/**
 * STS session policy Deny intersects role identity Allow for S3 PutObject.
 * Uses registered operator root and IAM principals (CTF rejects unregistered AKIDs).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StsSessionPolicyS3EnforcementIntegrationTest {

    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    @TestHTTPResource("/")
    URL endpoint;

    private String callerAkid;

    @BeforeAll
    void provisionCaller() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "session-policy-caller";
        CtfLabIamTestSupport.createUser(user);
        callerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String assumePolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}
            ]}""";
        CtfLabIamTestSupport.putUserPolicy(user, "assume-any", assumePolicy);
    }

    @Test
    void assumeRoleSessionPolicyDenyRestrictsS3PutObject() {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String bucket = "session-policy-" + suffix;
        String roleName = "SessionPolicyRole" + suffix;

        createBucket(bucket);
        createRole(roleName);
        putBroadS3RolePolicy(roleName, bucket);

        String accessKeyId = assumeRoleWithS3SessionPolicy(roleName, bucket);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(accessKeyId, "s3"))
                .contentType("text/plain")
                .body("allowed")
        .when()
                .put("/" + bucket + "/allowed/file.txt")
        .then()
                .statusCode(200);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(accessKeyId, "s3"))
                .contentType("text/plain")
                .body("denied")
        .when()
                .put("/" + bucket + "/blocked/file.txt")
        .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }

    private static void createBucket(String bucket) {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3"))
        .when()
                .put("/" + bucket)
        .then()
                .statusCode(200);
    }

    private static void createRole(String roleName) {
        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("Path", "/")
                .formParam("AssumeRolePolicyDocument", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Principal": { "AWS": "arn:aws:iam::%s:root" },
                          "Action": "sts:AssumeRole"
                        }
                      ]
                    }
                    """.formatted(ACCOUNT))
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private static void putBroadS3RolePolicy(String roleName, String bucket) {
        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", roleName)
                .formParam("PolicyName", "AllowS3")
                .formParam("PolicyDocument", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Action": "s3:*",
                          "Resource": [
                            "arn:aws:s3:::%1$s",
                            "arn:aws:s3:::%1$s/*"
                          ]
                        }
                      ]
                    }
                    """.formatted(bucket))
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "iam"))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private String assumeRoleWithS3SessionPolicy(String roleName, String bucket) {
        return given()
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + roleName)
                .formParam("RoleSessionName", "session-policy-test")
                .formParam("Policy", """
                    {
                      "Version": "2012-10-17",
                      "Statement": [
                        {
                          "Effect": "Allow",
                          "Action": "s3:*",
                          "Resource": [
                            "arn:aws:s3:::%1$s",
                            "arn:aws:s3:::%1$s/*"
                          ]
                        },
                        {
                          "Effect": "Deny",
                          "Action": "s3:*",
                          "Resource": "arn:aws:s3:::%1$s/blocked/*"
                        }
                      ]
                    }
                    """.formatted(bucket))
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(callerAkid))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"))
                .extract()
                .path("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
    }
}
