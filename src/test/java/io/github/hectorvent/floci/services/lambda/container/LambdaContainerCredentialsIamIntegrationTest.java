package io.github.hectorvent.floci.services.lambda.container;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.LambdaContainerCredentialsIamProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end: Lambda container credentials issue ASIA keys that honor the execution role IAM policy.
 */
@QuarkusTest
@TestProfile(LambdaContainerCredentialsIamProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LambdaContainerCredentialsIamIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String ROLE_NAME = "LambdaContainerCredS3Role";
    private static final String ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/" + ROLE_NAME;
    private static final String ALLOWED_BUCKET = "lambda-cred-allowed";
    private static final String DENIED_BUCKET = "lambda-cred-denied";
    private static final String ALLOWED_KEY = "object-allowed.txt";
    private static final String DENIED_KEY = "object-other.txt";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    LambdaContainerCredentialsServer credentialsServer;

    @Inject
    EmulatorConfig config;

    @Inject
    ObjectMapper objectMapper;

    private String credentialToken;
    private int credsPort;

    @BeforeAll
    void provision() throws Exception {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();
        credsPort = config.services().lambda().containerCredentialsPort();

        signedIamFormPost("Action=CreateRole"
                + "&RoleName=" + ROLE_NAME
                + "&AssumeRolePolicyDocument="
                + urlEncode("""
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},
                       "Action":"sts:AssumeRole"}
                    ]}"""));

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::%s/%s"}
            ]}""".formatted(ALLOWED_BUCKET, ALLOWED_KEY);
        signedIamFormPost("Action=PutRolePolicy"
                + "&RoleName=" + ROLE_NAME
                + "&PolicyName=ScopedS3Read"
                + "&PolicyDocument=" + urlEncode(policy));

        signedS3Put("/" + ALLOWED_BUCKET, "");
        signedS3Put("/" + DENIED_BUCKET, "");
        signedS3Put("/" + ALLOWED_BUCKET + "/" + ALLOWED_KEY, "sample-app-value");
        signedS3Put("/" + DENIED_BUCKET + "/" + DENIED_KEY, "denied-object");

        credentialToken = credentialsServer.registerFunction("cred-iam-fn", ROLE_ARN, REGION);
    }

    @Test
    void containerCredentialsAllowScopedS3GetAndDenyOtherBucket() throws Exception {
        HttpResponse<String> credsResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + credsPort + "/v2/credentials/" + credentialToken))
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, credsResponse.statusCode());

        JsonNode creds = objectMapper.readTree(credsResponse.body());
        String accessKeyId = creds.get("AccessKeyId").asText();
        String secretKey = creds.get("SecretAccessKey").asText();
        String sessionToken = creds.get("Token").asText();
        assertTrue(accessKeyId.startsWith("ASIA"));

        Instant now = Instant.now();
        SigV4HttpTestSupport.SignedRestHeaders allowed = SigV4HttpTestSupport.signRestGet(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + ALLOWED_BUCKET + "/" + ALLOWED_KEY,
                accessKeyId,
                secretKey,
                sessionToken,
                REGION,
                "s3",
                now);

        given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", allowed.authorization())
                .header("x-amz-date", allowed.amzDate())
                .header("x-amz-content-sha256", allowed.contentSha256())
                .header("x-amz-security-token", allowed.securityToken())
                .when().get("/" + ALLOWED_BUCKET + "/" + ALLOWED_KEY)
                .then().statusCode(200)
                .body(containsString("sample-app-value"));

        SigV4HttpTestSupport.SignedRestHeaders denied = SigV4HttpTestSupport.signRestGet(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + DENIED_BUCKET + "/" + DENIED_KEY,
                accessKeyId,
                secretKey,
                sessionToken,
                REGION,
                "s3",
                now);

        given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", denied.authorization())
                .header("x-amz-date", denied.amzDate())
                .header("x-amz-content-sha256", denied.contentSha256())
                .header("x-amz-security-token", denied.securityToken())
                .when().get("/" + DENIED_BUCKET + "/" + DENIED_KEY)
                .then().statusCode(403);
    }

    private void signedIamFormPost(String formBody) throws Exception {
        SigV4HttpTestSupport.SignedHeaders signed = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                CtfComposeParityProfile.ROOT_ACCESS_KEY_ID,
                CtfComposeParityProfile.ROOT_SECRET,
                REGION,
                "iam",
                formBody,
                Instant.now());

        given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(formBody)
                .when().post("/")
                .then().statusCode(200);
    }

    private void signedS3Put(String path, String body) throws Exception {
        byte[] payload = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        SigV4HttpTestSupport.SignedRestHeaders signed = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                payload,
                CtfComposeParityProfile.ROOT_ACCESS_KEY_ID,
                CtfComposeParityProfile.ROOT_SECRET,
                null,
                REGION,
                "s3",
                Instant.now());

        var spec = given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256());
        if (body.isEmpty()) {
            spec.when().put(path).then().statusCode(200);
        } else {
            spec.body(body).when().put(path).then().statusCode(200);
        }
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }
}
