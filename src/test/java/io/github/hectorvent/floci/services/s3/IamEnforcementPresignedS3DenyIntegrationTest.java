package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * Verified presigned GET is denied when the signing principal's identity policy
 * explicitly denies {@code s3:GetObject} (SigV4 signature still valid).
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamEnforcementPresignedS3DenyIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String BUCKET = "presign-identity-deny-bucket";
    private static final String KEY = "object.txt";
    private static final String BODY = "identity policy denies presigned get";
    private static final String USER = "presign-identity-deny-player";

    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;
    private String playerAccessKeyId;
    private String playerSecretAccessKey;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        signedIamFormPost("Action=CreateUser&UserName=" + USER);

        String createKeyBody = "Action=CreateAccessKey&UserName=" + USER;
        var createKeyResponse = signedIamFormPost(createKeyBody);
        playerAccessKeyId = createKeyResponse.extract().xmlPath()
                .getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
        playerSecretAccessKey = createKeyResponse.extract().xmlPath()
                .getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.SecretAccessKey");

        String objectArn = "arn:aws:s3:::" + BUCKET + "/" + KEY;
        String identityPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","Action":"s3:GetObject","Resource":"%s"}
            ]}""".formatted(objectArn);
        signedIamFormPost("Action=PutUserPolicy"
                + "&UserName=" + USER
                + "&PolicyName=PresignIdentityDeny"
                + "&PolicyDocument=" + urlEncode(identityPolicy));

        signedS3Put("/" + BUCKET, "");
        signedS3Put("/" + BUCKET + "/" + KEY, BODY);
    }

    @Test
    void presignedGetDeniedByIdentityPolicyAfterSignatureVerification() {
        PreSignedUrlGenerator presignGenerator = new PreSignedUrlGenerator(
                playerSecretAccessKey, playerAccessKeyId, 3600, true, REGION);
        String baseUrl = endpoint.toString().replaceAll("/$", "");
        String presignedUrl = presignGenerator.generatePresignedUrl(
                baseUrl, BUCKET, KEY, "GET", 3600);
        URI uri = URI.create(presignedUrl);

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
                .when()
                .get(uri.getRawPath() + "?" + uri.getRawQuery())
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }

    private io.restassured.response.ValidatableResponse signedIamFormPost(String formBody) throws Exception {
        SigV4HttpTestSupport.SignedHeaders signed = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "iam",
                formBody,
                Instant.now());

        return given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(formBody)
                .when()
                .post("/")
                .then()
                .statusCode(200);
    }

    private void signedS3Put(String path, String body) throws Exception {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        SigV4HttpTestSupport.SignedRestHeaders signed = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                payload,
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "s3",
                Instant.now());

        var spec = given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256());
        if (body.isEmpty()) {
            spec.when().put(path).then().statusCode(200);
        } else {
            spec.contentType("text/plain")
                    .body(body)
                    .when().put(path)
                    .then().statusCode(200);
        }
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
