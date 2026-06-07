package io.github.hectorvent.floci.services.secretsmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code secretsmanager:GetSecretValue} scoped to one secret ARN suffix wildcard.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SecretsManagerGetSecretValueScopedArnIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    private String playerAkid;
    private static final String ALLOWED = "ctf/lab/scoped-flag";
    private static final String DECOY = "ctf/lab/decoy-flag";

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-sm-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSm = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "secretsmanager");
        createSecret(rootSm, ALLOWED, "flag{scoped-read}");
        createSecret(rootSm, DECOY, "flag{decoy}");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
               "Resource":"arn:aws:secretsmanager:us-east-1:%s:secret:ctf/lab/scoped-flag-*"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "sm-read-one", policy);
    }

    private void createSecret(String auth, String name, String value) throws Exception {
        ObjectNode create = objectMapper.createObjectNode();
        create.put("Name", name);
        create.put("SecretString", value);
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType("application/x-amz-json-1.1")
                .body(create.toString())
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void getAllowedSecret() throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("SecretId", ALLOWED);
        given()
                .header("Authorization", playerSmAuth())
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("SecretString", equalTo("flag{scoped-read}"));
    }

    @Test
    void getDecoySecretDenied() throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("SecretId", DECOY);
        given()
                .header("Authorization", playerSmAuth())
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(403);
    }

    private String playerSmAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "secretsmanager");
    }
}
