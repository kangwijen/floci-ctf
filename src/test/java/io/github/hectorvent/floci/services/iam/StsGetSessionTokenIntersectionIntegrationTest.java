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

/**
 * {@code GetSessionToken} session policy is intersected with the parent IAM user policy.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StsGetSessionTokenIntersectionIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String parentAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "session-parent-user";
        CtfLabIamTestSupport.createUser(user);
        parentAkid = CtfLabIamTestSupport.createAccessKey(user);

        String parentPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::vault"}
            ]}""";
        CtfLabIamTestSupport.putUserPolicy(user, "list-only", parentPolicy);
    }

    @Test
    void sessionCredentialsDenyActionBeyondParentPolicy() {
        String sessionPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::vault/*"}
            ]}""";

        String sessionAkid = given()
                .formParam("Action", "GetSessionToken")
                .formParam("Policy", sessionPolicy)
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(parentAkid))
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("GetSessionTokenResponse.GetSessionTokenResult.Credentials.AccessKeyId");

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(sessionAkid, "s3"))
                .when().get("/vault/flag.txt")
                .then().statusCode(403);
    }
}
