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

import static io.restassured.RestAssured.given;

/**
 * {@code GetFederationToken} session policy is intersected with the parent IAM user policy.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StsGetFederationTokenIntersectionIntegrationTest {

    @TestHTTPResource("/")
    URL endpoint;

    private String parentAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "federation-test-user";
        CtfLabIamTestSupport.createUser(user);
        parentAkid = CtfLabIamTestSupport.createAccessKey(user);

        String parentPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::vault"},
              {"Effect":"Allow","Action":"sts:GetFederationToken","Resource":"*"}
            ]}""";
        CtfLabIamTestSupport.putUserPolicy(user, "list-only", parentPolicy);
    }

    @Test
    void federationCredentialsDenyActionBeyondParentPolicy() {
        String sessionPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::vault/*"}
            ]}""";

        String sessionAkid = given()
                .formParam("Action", "GetFederationToken")
                .formParam("Name", "federated-session")
                .formParam("Policy", sessionPolicy)
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(parentAkid))
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("GetFederationTokenResponse.GetFederationTokenResult.Credentials.AccessKeyId");

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(sessionAkid, "s3"))
                .when().get("/vault/denied-object.txt")
                .then().statusCode(403);
    }
}
