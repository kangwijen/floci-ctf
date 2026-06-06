package io.github.hectorvent.floci.services.secretsmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * F10: KMS-wrapped {@code SecretBinary} compatible with {@code aws kms decrypt}.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
class SecretsManagerKmsEnvelopeIntegrationTest {

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
    void getSecretValueReturnsKmsCiphertextBlobRoundTrip() throws Exception {
        String kmsAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/kms/aws4_request";
        String smAuth = kmsAuth.replace("/kms/", "/secretsmanager/");

        String keyId = given()
                .header("Authorization", kmsAuth)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode create = objectMapper.createObjectNode();
        create.put("Name", "ctf/kms-envelope-flag");
        create.put("SecretString", "flag{kms-envelope}");
        create.put("KmsKeyId", keyId);

        given()
                .header("Authorization", smAuth)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .contentType("application/x-amz-json-1.1")
                .body(create.toString())
                .when().post("/")
                .then().statusCode(200);

        String secretBinaryB64 = given()
                .header("Authorization", smAuth)
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().put("SecretId", "ctf/kms-envelope-flag").toString())
                .when().post("/")
                .then().statusCode(200)
                .body("SecretString", nullValue())
                .body("SecretBinary", notNullValue())
                .extract().jsonPath().getString("SecretBinary");

        byte[] ciphertext = Base64.getDecoder().decode(secretBinaryB64);

        ObjectNode decryptReq = objectMapper.createObjectNode();
        decryptReq.put("CiphertextBlob", Base64.getEncoder().encodeToString(ciphertext));
        decryptReq.put("KeyId", keyId);

        String plaintextB64 = given()
                .header("Authorization", kmsAuth)
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType("application/x-amz-json-1.1")
                .body(decryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("Plaintext");

        assertEquals("flag{kms-envelope}", new String(Base64.getDecoder().decode(plaintextB64)));
    }
}
