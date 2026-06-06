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
 * F8: strict mode denies unmapped or unrelated IAM actions for least-privilege principals.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamStrictUnmappedActionIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-strict-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"},
              {"Effect":"Deny","Action":"iam:*","Resource":"*"}
            ]}""";
        CtfLabIamTestSupport.putUserPolicy(user, "caller-only", policy);
    }

    @Test
    void listUsersDeniedDespiteWildcardResourceInUnrelatedPolicy() {
        given()
                .formParam("Action", "ListUsers")
                .header("Authorization", CtfLabIamTestSupport.playerIamAuth(playerAkid))
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    void getCallerIdentityStillAllowed() {
        given()
                .formParam("Action", "GetCallerIdentity")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(playerAkid))
                .when().post("/")
                .then().statusCode(200);
    }
}
