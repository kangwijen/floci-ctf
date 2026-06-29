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
import static org.hamcrest.Matchers.equalTo;

/**
 * Regression: SigV4 credential scope must match JSON 1.1 {@code X-Amz-Target} service.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamJson11CredentialScopeSplitIntegrationTest {

    private static final String JSON_11 = "application/x-amz-json-1.1";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "json11-scope-split-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);
        CtfLabIamTestSupport.putUserPolicy(user, "s3-only", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:*","Resource":"*"},
              {"Effect":"Deny","Action":"secretsmanager:*","Resource":"*"}
            ]}""");
        given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .contentType(JSON_11)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .body("{\"Name\":\"scope-split-target\",\"SecretString\":\"poc-value\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    @Test
    void s3ScopedSigV4CannotListSecretsWhenTargetIsSecretsManager() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "s3"))
                .contentType(JSON_11)
                .header("X-Amz-Target", "secretsmanager.ListSecrets")
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }
}
