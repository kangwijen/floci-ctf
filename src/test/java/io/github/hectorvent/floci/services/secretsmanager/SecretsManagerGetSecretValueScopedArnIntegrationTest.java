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

    @Test
    void getAllowedSecretWithPathPrefixWildcard() throws Exception {
        String user = "ctf-sm-path-player";
        CtfLabIamTestSupport.createUser(user);
        String akid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSm = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "secretsmanager");
        String secretName = "app/live/deadbeef";
        createSecret(rootSm, secretName, "flag{path-prefix}");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
               "Resource":"arn:aws:secretsmanager:us-east-1:%s:secret:app/live/*"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "sm-path-prefix", policy);

        ObjectNode req = objectMapper.createObjectNode();
        req.put("SecretId", secretName);
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(akid, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("SecretString", equalTo("flag{path-prefix}"));
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
    void getAllowedSecretWithAwsQuestionMarkSuffixPolicy() throws Exception {
        String user = "ctf-sm-qmark-player";
        CtfLabIamTestSupport.createUser(user);
        String akid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSm = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "secretsmanager");
        String secretName = "app/live/qmark-test";
        createSecret(rootSm, secretName, "flag{qmark-suffix}");

        String storedArn = given()
                .header("Authorization", rootSm)
                .header("X-Amz-Target", "secretsmanager.DescribeSecret")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().put("SecretId", secretName).toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("ARN");

        int suffixDash = storedArn.lastIndexOf('-');
        String policyResource = storedArn.substring(0, suffixDash) + "-??????";
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
               "Resource":"%s"}
            ]}""".formatted(policyResource);
        CtfLabIamTestSupport.putUserPolicy(user, "sm-qmark-suffix", policy);

        ObjectNode req = objectMapper.createObjectNode();
        req.put("SecretId", secretName);
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(akid, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("SecretString", equalTo("flag{qmark-suffix}"));
    }

    @Test
    void getPathPrefixSecretDeniedWithHyphenWildcard() throws Exception {
        String user = "ctf-sm-hyphen-player";
        CtfLabIamTestSupport.createUser(user);
        String akid = CtfLabIamTestSupport.createAccessKey(user);

        String rootSm = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "secretsmanager");
        String secretName = "app/live/hyphen-test";
        createSecret(rootSm, secretName, "flag{hyphen-deny}");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
               "Resource":"arn:aws:secretsmanager:us-east-1:%s:secret:app/live-*"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "sm-hyphen-wildcard", policy);

        ObjectNode req = objectMapper.createObjectNode();
        req.put("SecretId", secretName);
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(akid, "secretsmanager"))
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(403);
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
