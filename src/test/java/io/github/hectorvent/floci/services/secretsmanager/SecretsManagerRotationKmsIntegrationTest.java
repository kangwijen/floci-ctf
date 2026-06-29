package io.github.hectorvent.floci.services.secretsmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Rotation-style {@code PutSecretValue} with a pre-wrapped KMS envelope must not
 * double-wrap; one {@code kms:Decrypt} on {@code GetSecretValue} output yields plaintext.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
class SecretsManagerRotationKmsIntegrationTest {

    private static final String ROTATION_TOKEN = "01234567890123456789012345678901";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    @BeforeEach
    void bindHttp() {
        io.github.hectorvent.floci.testing.RestAssuredJsonUtils.configureAwsContentTypes();
        CtfLabIamTestSupport.bindRestAssured(endpoint);
    }

    @Test
    void putSecretValueWithPreWrappedEnvelopeDuringRotationDoesNotDoubleWrap() throws Exception {
        String rootKmsAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";
        String rootSmAuth = rootKmsAuth.replace("/kms/", "/secretsmanager/");

        String keyId = given()
                .header("Authorization", rootKmsAuth)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        String secretName = "test/kms-rotation-envelope";
        ObjectNode create = objectMapper.createObjectNode();
        create.put("Name", secretName);
        create.put("SecretString", "initial-rotation-plaintext");
        create.put("KmsKeyId", keyId);
        given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType("application/x-amz-json-1.1")
                .body(create.toString())
                .when().post("/")
                .then().statusCode(200);

        String rotatedPlaintext = "rotated-kms-plaintext-04";
        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", keyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString(rotatedPlaintext.getBytes()));

        String envelopeB64 = given()
                .header("Authorization", rootKmsAuth)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType("application/x-amz-json-1.1")
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        ObjectNode put = objectMapper.createObjectNode();
        put.put("SecretId", secretName);
        put.put("SecretBinary", envelopeB64);
        put.put("ClientRequestToken", ROTATION_TOKEN);
        ArrayNode stages = objectMapper.createArrayNode();
        stages.add("AWSPENDING");
        put.set("VersionStages", stages);

        given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.PutSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(put.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("VersionId", equalTo(ROTATION_TOKEN));

        String secretBinaryB64 = given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode()
                        .put("SecretId", secretName)
                        .put("VersionStage", "AWSPENDING")
                        .toString())
                .when().post("/")
                .then().statusCode(200)
                .body("SecretString", nullValue())
                .body("SecretBinary", equalTo(envelopeB64))
                .extract().jsonPath().getString("SecretBinary");

        ObjectNode decryptReq = objectMapper.createObjectNode();
        decryptReq.put("CiphertextBlob", secretBinaryB64);

        String plaintextB64 = given()
                .header("Authorization", rootKmsAuth)
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(decryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("Plaintext");

        String decrypted = new String(Base64.getDecoder().decode(plaintextB64));
        assertEquals(rotatedPlaintext, decrypted);
        assertFalse(decrypted.startsWith("kms:v2:"));
    }

    @Test
    void putSecretValueWithPreWrappedSecretStringPromotesToCurrentWithoutDoubleWrap() throws Exception {
        String rootKmsAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";
        String rootSmAuth = rootKmsAuth.replace("/kms/", "/secretsmanager/");

        String keyId = given()
                .header("Authorization", rootKmsAuth)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        String secretName = "test/kms-rotation-finish";
        ObjectNode create = objectMapper.createObjectNode();
        create.put("Name", secretName);
        create.put("SecretString", "before-rotation");
        create.put("KmsKeyId", keyId);
        String currentVersionId = given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType("application/x-amz-json-1.1")
                .body(create.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("VersionId");

        String rotatedPlaintext = "finish-rotation-plaintext";
        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", keyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString(rotatedPlaintext.getBytes()));

        String envelopeB64 = given()
                .header("Authorization", rootKmsAuth)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType("application/x-amz-json-1.1")
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        ObjectNode putPending = objectMapper.createObjectNode();
        putPending.put("SecretId", secretName);
        putPending.put("SecretString", envelopeB64);
        putPending.put("ClientRequestToken", ROTATION_TOKEN);
        ArrayNode pendingStages = objectMapper.createArrayNode();
        pendingStages.add("AWSPENDING");
        putPending.set("VersionStages", pendingStages);

        given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.PutSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(putPending.toString())
                .when().post("/")
                .then().statusCode(200);

        ObjectNode promote = objectMapper.createObjectNode();
        promote.put("SecretId", secretName);
        promote.put("VersionStage", "AWSCURRENT");
        promote.put("MoveToVersionId", ROTATION_TOKEN);
        promote.put("RemoveFromVersionId", currentVersionId);

        given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.UpdateSecretVersionStage")
                .contentType("application/x-amz-json-1.1")
                .body(promote.toString())
                .when().post("/")
                .then().statusCode(200);

        String secretBinaryB64 = given()
                .header("Authorization", rootSmAuth)
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().put("SecretId", secretName).toString())
                .when().post("/")
                .then().statusCode(200)
                .body("SecretString", nullValue())
                .body("SecretBinary", equalTo(envelopeB64))
                .extract().jsonPath().getString("SecretBinary");

        ObjectNode decryptReq = objectMapper.createObjectNode();
        decryptReq.put("CiphertextBlob", secretBinaryB64);

        String plaintextB64 = given()
                .header("Authorization", rootKmsAuth)
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(decryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("Plaintext");

        assertEquals(rotatedPlaintext, new String(Base64.getDecoder().decode(plaintextB64)));
    }
}
