package io.github.hectorvent.floci.services.kms;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * {@code kms:Decrypt} scoped to one CMK via {@link io.github.hectorvent.floci.services.iam.ResourceArnBuilder}.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KmsDecryptScopedKeyIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    private String playerAkid;
    private String allowedKeyId;
    private byte[] ciphertext;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "kms-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";

        allowedKeyId = given()
                .header("Authorization", rootAuth)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", allowedKeyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString("lab-plaintext".getBytes()));

        String ciphertextB64 = given()
                .header("Authorization", rootAuth)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType("application/x-amz-json-1.1")
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        ciphertext = Base64.getDecoder().decode(ciphertextB64);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"kms:Decrypt",
               "Resource":"arn:aws:kms:us-east-1:%s:key/%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, allowedKeyId);
        CtfLabIamTestSupport.putUserPolicy(user, "kms-decrypt-one", policy);
    }

    @Test
    @Order(1)
    void decryptAllowedKeySucceeds() throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("CiphertextBlob", Base64.getEncoder().encodeToString(ciphertext));

        String plaintextB64 = given()
                .header("Authorization", CtfLabIamTestSupport.playerAuth(playerAkid).replace("/s3/", "/kms/"))
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("Plaintext");

        assertEquals("lab-plaintext", new String(Base64.getDecoder().decode(plaintextB64)));
    }

    @Test
    @Order(3)
    void decryptViaKeyPolicyWithoutIdentityPolicy() throws Exception {
        String rootAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";
        String playerArn = "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":user/kms-test-user";
        String keyPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"%s"},
               "Action":"kms:Decrypt",
               "Resource":"*"}
            ]}""".formatted(playerArn);

        ObjectNode putPolicy = objectMapper.createObjectNode();
        putPolicy.put("KeyId", allowedKeyId);
        putPolicy.put("Policy", keyPolicy);
        given()
                .header("Authorization", rootAuth)
                .header("X-Amz-Target", "TrentService.PutKeyPolicy")
                .contentType("application/x-amz-json-1.1")
                .body(putPolicy.toString())
                .when().post("/")
                .then().statusCode(200);

        CtfLabIamTestSupport.putUserPolicy("kms-test-user", "kms-decrypt-one", """
            {"Version":"2012-10-17","Statement":[]}""");

        ObjectNode req = objectMapper.createObjectNode();
        req.put("CiphertextBlob", Base64.getEncoder().encodeToString(ciphertext));

        String plaintextB64 = given()
                .header("Authorization", CtfLabIamTestSupport.playerAuth(playerAkid).replace("/s3/", "/kms/"))
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("Plaintext");

        assertEquals("lab-plaintext", new String(Base64.getDecoder().decode(plaintextB64)));
    }

    @Test
    @Order(4)
    void decryptViaGrantWithoutIdentityPolicy() throws Exception {
        String rootAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";
        String playerArn = "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":user/kms-test-user";

        ObjectNode grantReq = objectMapper.createObjectNode();
        grantReq.put("KeyId", allowedKeyId);
        grantReq.put("GranteePrincipal", playerArn);
        grantReq.putArray("Operations").add("Decrypt");
        given()
                .header("Authorization", rootAuth)
                .header("X-Amz-Target", "TrentService.CreateGrant")
                .contentType("application/x-amz-json-1.1")
                .body(grantReq.toString())
                .when().post("/")
                .then().statusCode(200);

        CtfLabIamTestSupport.putUserPolicy("kms-test-user", "kms-decrypt-one", """
            {"Version":"2012-10-17","Statement":[]}""");

        ObjectNode req = objectMapper.createObjectNode();
        req.put("CiphertextBlob", Base64.getEncoder().encodeToString(ciphertext));

        String plaintextB64 = given()
                .header("Authorization", CtfLabIamTestSupport.playerAuth(playerAkid).replace("/s3/", "/kms/"))
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("Plaintext");

        assertEquals("lab-plaintext", new String(Base64.getDecoder().decode(plaintextB64)));
    }

    @Test
    @Order(2)
    void decryptWithWrongKeyInPolicyDenied() throws Exception {
        String rootAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";
        String otherKeyId = given()
                .header("Authorization", rootAuth)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        String narrowPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"kms:Decrypt",
               "Resource":"arn:aws:kms:us-east-1:%s:key/%s"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT, otherKeyId);
        CtfLabIamTestSupport.putUserPolicy("kms-test-user", "kms-decrypt-one", narrowPolicy);

        ObjectNode req = objectMapper.createObjectNode();
        req.put("CiphertextBlob", Base64.getEncoder().encodeToString(ciphertext));

        given()
                .header("Authorization", CtfLabIamTestSupport.playerAuth(playerAkid).replace("/s3/", "/kms/"))
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(403);
    }
}
