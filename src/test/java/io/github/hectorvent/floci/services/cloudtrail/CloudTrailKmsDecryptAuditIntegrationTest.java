package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.github.hectorvent.floci.testsupport.CloudTrailForwardedHeadersAuditProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * KMS {@code Decrypt} HTTP audit records {@code requestParameters.keyId} when only
 * {@code CiphertextBlob} is sent, matching AWS CloudTrail field fidelity.
 */
@QuarkusTest
@TestProfile(CloudTrailForwardedHeadersAuditProfile.class)
class CloudTrailKmsDecryptAuditIntegrationTest {

    private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
    private static final String CLOUDTRAIL_TARGET =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    private static final String KMS_AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIATEST00000001/20260227/us-east-1/kms/aws4_request";

    @Inject
    CloudTrailEventStore eventStore;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    static void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
    }

    @BeforeEach
    void resetStore() {
        eventStore.clear();
    }

    @Test
    void decryptWithCiphertextBlobOnlyRecordsKeyIdAndResources() throws Exception {
        provisionLoggingTrail("kms-audit-trail-bucket", "kms-audit-trail");

        String keyId = given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType(CONTENT_TYPE)
                .body("{}")
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", keyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString("audit-plaintext".getBytes()));

        String ciphertextB64 = given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType(CONTENT_TYPE)
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        ObjectNode decryptReq = objectMapper.createObjectNode();
        decryptReq.put("CiphertextBlob", ciphertextB64);

        given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.Decrypt")
                .header("X-Forwarded-For", "203.0.113.44")
                .contentType(CONTENT_TYPE)
                .body(decryptReq.toString())
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("Decrypt", "kms.amazonaws.com");
        assertEquals("kms.amazonaws.com", event.path("eventSource").asText());
        assertEquals("203.0.113.44", event.path("sourceIPAddress").asText());
        assertTrue(event.path("readOnly").asBoolean());
        assertEquals("SYMMETRIC_DEFAULT",
                event.path("requestParameters").path("encryptionAlgorithm").asText());
        String recordedKeyId = event.path("requestParameters").path("keyId").asText();
        assertTrue(recordedKeyId.contains(keyId), "expected key id in requestParameters.keyId");
        assertFalse(event.path("requestParameters").has("CiphertextBlob"));
        assertFalse(event.path("requestParameters").has("ciphertextBlob"));
        assertEquals("AWS::KMS::Key", event.path("resources").get(0).path("type").asText());
    }

    @Test
    void decryptWithExplicitKeyIdRecordsFullKeyArn() throws Exception {
        provisionLoggingTrail("kms-explicit-trail-bucket", "kms-explicit-trail");

        String keyId = given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType(CONTENT_TYPE)
                .body("{}")
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", keyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString("explicit-key-plaintext".getBytes()));

        String ciphertextB64 = given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType(CONTENT_TYPE)
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        ObjectNode decryptReq = objectMapper.createObjectNode();
        decryptReq.put("KeyId", keyId);
        decryptReq.put("CiphertextBlob", ciphertextB64);

        given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType(CONTENT_TYPE)
                .body(decryptReq.toString())
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("Decrypt", "kms.amazonaws.com");
        String expectedArn = "arn:aws:kms:us-east-1:000000000000:key/" + keyId;
        assertEquals(expectedArn, event.path("requestParameters").path("keyId").asText());
        assertEquals(expectedArn, event.path("resources").get(0).path("ARN").asText());
        assertEquals("000000000000", event.path("resources").get(0).path("accountId").asText());
        assertTrue(event.path("managementEvent").asBoolean());
        assertEquals("Management", event.path("eventCategory").asText());
        assertTrue(event.path("readOnly").asBoolean());
        assertTrue(event.path("responseElements").isNull()
                || event.path("responseElements").isMissingNode());
    }

    @Test
    void decryptWithEncryptionContextRecordsEncryptionContext() throws Exception {
        provisionLoggingTrail("kms-ctx-trail-bucket", "kms-ctx-trail");

        String keyId = given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType(CONTENT_TYPE)
                .body("{}")
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", keyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString("ctx-plaintext".getBytes()));
        ObjectNode encryptionContext = objectMapper.createObjectNode();
        encryptionContext.put("purpose", "audit-test");
        encryptReq.set("EncryptionContext", encryptionContext);

        String ciphertextB64 = given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType(CONTENT_TYPE)
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        ObjectNode decryptReq = objectMapper.createObjectNode();
        decryptReq.put("CiphertextBlob", ciphertextB64);
        decryptReq.set("EncryptionContext", encryptionContext);

        given()
                .header("Authorization", KMS_AUTH)
                .header("X-Amz-Target", "TrentService.Decrypt")
                .contentType(CONTENT_TYPE)
                .body(decryptReq.toString())
                .when().post("/")
                .then().statusCode(200);

        JsonNode event = lookupSingleEvent("Decrypt", "kms.amazonaws.com");
        assertEquals("audit-test",
                event.path("requestParameters").path("encryptionContext").path("purpose").asText());
    }

    private void provisionLoggingTrail(String trailBucket, String trailName) {
        given().when().put("/" + trailBucket).then().statusCode(200);
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "CreateTrail")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\",\"S3BucketName\":\"%s\"}".formatted(trailName, trailBucket))
                .when().post("/")
                .then().statusCode(200);
        given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "StartLogging")
                .contentType(CONTENT_TYPE)
                .body("{\"Name\":\"%s\"}".formatted(trailName))
                .when().post("/")
                .then().statusCode(200);
    }

    private JsonNode lookupSingleEvent(String eventName, String eventSource) throws Exception {
        String cloudTrailJson = given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET + "LookupEvents")
                .contentType(CONTENT_TYPE)
                .body("""
                        {
                            "LookupAttributes": [
                                {"AttributeKey": "EventName", "AttributeValue": "%s"}
                            ]
                        }
                        """.formatted(eventName))
                .when().post("/")
                .then().statusCode(200)
                .body("Events", hasSize(1))
                .body("Events[0].EventName", equalTo(eventName))
                .body("Events[0].EventSource", equalTo(eventSource))
                .extract().path("Events[0].CloudTrailEvent");
        return objectMapper.readTree(cloudTrailJson);
    }
}
