package io.github.hectorvent.floci.services.stepfunctions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URL;
import java.util.Base64;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Step Functions AWS SDK task integrations with {@link io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer}.
 *
 * <p>Resources:
 * <ul>
 *   <li>{@code arn:aws:states:::aws-sdk:secretsmanager:getSecretValue}</li>
 *   <li>{@code arn:aws:states:::aws-sdk:kms:decrypt}</li>
 *   <li>{@code arn:aws:states:::aws-sdk:s3:getObject}</li>
 * </ul>
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StepFunctionsScopedSdkIamIntegrationTest {

    private static final String SFN_CONTENT_TYPE = "application/x-amz-json-1.0";
    private static final String REGION = "us-east-1";
    private static final String ROLE_NAME = "SfnScopedSdkExecRole";
    private static final String ROLE_ARN =
            "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":role/" + ROLE_NAME;

    private static final String ALLOWED_SECRET = "test/sfn/allowed-secret";
    private static final String DECOY_SECRET = "test/sfn/other-secret";
    private static final String BUCKET = "sfn-scoped-bucket";
    private static final String ALLOWED_KEY = "allowed-key";
    private static final String DECOY_KEY = "other-key";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    private String allowedKeyId;
    private byte[] ciphertext;
    private String execRoleArn;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        execRoleArn = ROLE_ARN;

        given()
                .formParam("Action", "CreateRole")
                .formParam("RoleName", ROLE_NAME)
                .formParam("AssumeRolePolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"Service":"states.amazonaws.com"},
                       "Action":"sts:AssumeRole"}
                    ]}""")
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        String rootSm = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "secretsmanager");
        createSecret(rootSm, ALLOWED_SECRET, "allowed-secret-value");
        createSecret(rootSm, DECOY_SECRET, "other-secret-value");

        String rootKms = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "kms");
        allowedKeyId = given()
                .header("Authorization", rootKms)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", allowedKeyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString("sfn-plaintext".getBytes()));
        String ciphertextB64 = given()
                .header("Authorization", rootKms)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType("application/x-amz-json-1.1")
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");
        ciphertext = Base64.getDecoder().decode(ciphertextB64);

        String rootS3 = CtfLabIamTestSupport.playerAuth(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID);
        given().header("Authorization", rootS3).when().put("/" + BUCKET).then().statusCode(200);
        given().header("Authorization", rootS3).body("allowed-object-value").when().put("/" + BUCKET + "/" + ALLOWED_KEY)
                .then().statusCode(200);
        given().header("Authorization", rootS3).body("decoy-object").when().put("/" + BUCKET + "/" + DECOY_KEY)
                .then().statusCode(200);

        given()
                .formParam("Action", "PutRolePolicy")
                .formParam("RoleName", ROLE_NAME)
                .formParam("PolicyName", "ScopedSdkAccess")
                .formParam("PolicyDocument", """
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
                       "Resource":"arn:aws:secretsmanager:%s:%s:secret:%s-*"},
                      {"Effect":"Allow","Action":"kms:Decrypt",
                       "Resource":"arn:aws:kms:%s:%s:key/%s"},
                      {"Effect":"Allow","Action":"s3:GetObject",
                       "Resource":"arn:aws:s3:::%s/%s"}
                    ]}""".formatted(
                        REGION, CtfLabIamEnforcementProfile.ACCOUNT, ALLOWED_SECRET,
                        REGION, CtfLabIamEnforcementProfile.ACCOUNT, allowedKeyId,
                        BUCKET, ALLOWED_KEY))
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
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
    @Order(1)
    void getSecretValue_allowedSecret() throws Exception {
        String output = executeSfn("sm-allowed",
                "arn:aws:states:::aws-sdk:secretsmanager:getSecretValue",
                """
                {"SecretId":"%s"}
                """.formatted(ALLOWED_SECRET));

        JsonNode result = objectMapper.readTree(output);
        assertEquals("allowed-secret-value", result.path("SecretString").asText());
    }

    @Test
    @Order(2)
    void getSecretValue_decoySecretDenied() throws Exception {
        Response failed = executeSfnExpectFailure("sm-decoy",
                "arn:aws:states:::aws-sdk:secretsmanager:getSecretValue",
                """
                {"SecretId":"%s"}
                """.formatted(DECOY_SECRET));
        assertEquals("SecretsManager.AccessDeniedException", failed.jsonPath().getString("error"));
    }

    @Test
    @Order(3)
    void kmsDecrypt_allowedKey() throws Exception {
        String output = executeSfn("kms-allowed",
                "arn:aws:states:::aws-sdk:kms:decrypt",
                """
                {"CiphertextBlob":"%s"}
                """.formatted(Base64.getEncoder().encodeToString(ciphertext)));

        JsonNode result = objectMapper.readTree(output);
        String plaintext = new String(Base64.getDecoder().decode(result.path("Plaintext").asText()));
        assertEquals("sfn-plaintext", plaintext);
    }

    @Test
    @Order(4)
    void kmsDecrypt_otherKeyDenied() throws Exception {
        String rootKms = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "kms");
        String otherKeyId = given()
                .header("Authorization", rootKms)
                .header("X-Amz-Target", "TrentService.CreateKey")
                .contentType("application/x-amz-json-1.1")
                .body(objectMapper.createObjectNode().toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("KeyMetadata.KeyId");

        ObjectNode encryptReq = objectMapper.createObjectNode();
        encryptReq.put("KeyId", otherKeyId);
        encryptReq.put("Plaintext", Base64.getEncoder().encodeToString("other".getBytes()));
        String otherCiphertextB64 = given()
                .header("Authorization", rootKms)
                .header("X-Amz-Target", "TrentService.Encrypt")
                .contentType("application/x-amz-json-1.1")
                .body(encryptReq.toString())
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("CiphertextBlob");

        Response failed = executeSfnExpectFailure("kms-decoy",
                "arn:aws:states:::aws-sdk:kms:decrypt",
                """
                {"CiphertextBlob":"%s"}
                """.formatted(otherCiphertextB64));
        assertEquals("Kms.AccessDeniedException", failed.jsonPath().getString("error"));
    }

    @Test
    @Order(5)
    void s3GetObject_allowedKey() throws Exception {
        String output = executeSfn("s3-allowed",
                "arn:aws:states:::aws-sdk:s3:getObject",
                """
                {"Bucket":"%s","Key":"%s"}
                """.formatted(BUCKET, ALLOWED_KEY));

        JsonNode result = objectMapper.readTree(output);
        String body = new String(Base64.getDecoder().decode(result.path("Body").asText()));
        assertEquals("allowed-object-value", body);
    }

    @Test
    @Order(6)
    void s3GetObject_decoyKeyDenied() throws Exception {
        Response failed = executeSfnExpectFailure("s3-decoy",
                "arn:aws:states:::aws-sdk:s3:getObject",
                """
                {"Bucket":"%s","Key":"%s"}
                """.formatted(BUCKET, DECOY_KEY));
        assertEquals("S3.AccessDeniedException", failed.jsonPath().getString("error"));
    }

    private String executeSfn(String nameSuffix, String resource, String parameters) throws Exception {
        String definition = buildStateMachineDefinition(resource, parameters);
        String smArn = createStateMachine(nameSuffix + "-" + System.currentTimeMillis(), definition);
        String execArn = startExecution(smArn, "{}");
        return waitForExecution(execArn);
    }

    private Response executeSfnExpectFailure(String nameSuffix, String resource, String parameters) throws Exception {
        String definition = buildStateMachineDefinition(resource, parameters);
        String smArn = createStateMachine(nameSuffix + "-" + System.currentTimeMillis(), definition);
        String execArn = startExecution(smArn, "{}");
        return waitForFailedExecution(execArn);
    }

    private String buildStateMachineDefinition(String resource, String parameters) {
        return """
                {
                    "StartAt": "Action",
                    "States": {
                        "Action": {
                            "Type": "Task",
                            "Resource": "%s",
                            "Parameters": %s,
                            "End": true
                        }
                    }
                }
                """.formatted(resource, parameters.strip());
    }

    private String createStateMachine(String name, String definition) {
        Response resp = given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .header("X-Amz-Target", "AWSStepFunctions.CreateStateMachine")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {
                            "name": "%s",
                            "definition": %s,
                            "roleArn": "%s"
                        }
                        """.formatted(name, quote(definition), execRoleArn))
                .when()
                .post("/");
        resp.then().statusCode(200);
        return resp.jsonPath().getString("stateMachineArn");
    }

    private String startExecution(String smArn, String input) {
        Response resp = given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .header("X-Amz-Target", "AWSStepFunctions.StartExecution")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {
                            "stateMachineArn": "%s",
                            "input": %s
                        }
                        """.formatted(smArn, quote(input)))
                .when()
                .post("/");
        resp.then().statusCode(200);
        return resp.jsonPath().getString("executionArn");
    }

    private String waitForExecution(String execArn) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            Response resp = describeExecution(execArn);
            String status = resp.jsonPath().getString("status");
            if ("SUCCEEDED".equals(status)) {
                return resp.jsonPath().getString("output");
            }
            if ("FAILED".equals(status) || "ABORTED".equals(status)) {
                fail("Execution " + status + ": " + resp.body().asString());
            }
            Thread.sleep(100);
        }
        fail("Execution did not complete within timeout");
        return null;
    }

    private Response waitForFailedExecution(String execArn) throws InterruptedException {
        for (int i = 0; i < 50; i++) {
            Response resp = describeExecution(execArn);
            String status = resp.jsonPath().getString("status");
            if ("FAILED".equals(status)) {
                return resp;
            }
            if ("SUCCEEDED".equals(status)) {
                fail("Execution should have failed but succeeded: " + resp.body().asString());
            }
            Thread.sleep(100);
        }
        fail("Execution did not complete within timeout");
        return null;
    }

    private Response describeExecution(String execArn) {
        return given()
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .header("X-Amz-Target", "AWSStepFunctions.DescribeExecution")
                .contentType(SFN_CONTENT_TYPE)
                .body("""
                        {"executionArn": "%s"}
                        """.formatted(execArn))
                .when()
                .post("/");
    }

    private static String quote(String raw) {
        return "\"" + raw
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                + "\"";
    }
}
