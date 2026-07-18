package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * Verified presigned POST must run identity + bucket policy after signature verification.
 * A valid SigV4 POST policy must not bypass {@code IamEnforcementFilter}.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class IamEnforcementPresignedPostDenyIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String BUCKET = "presign-post-identity-deny-bucket";
    private static final String KEY = "uploads/denied-post.txt";
    private static final String USER = "presign-post-identity-deny-player";
    private static final DateTimeFormatter AMZ_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

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
              {"Effect":"Deny","Action":"s3:PutObject","Resource":"%s"}
            ]}""".formatted(objectArn);
        signedIamFormPost("Action=PutUserPolicy"
                + "&UserName=" + USER
                + "&PolicyName=PresignPostIdentityDeny"
                + "&PolicyDocument=" + urlEncode(identityPolicy));

        signedS3Put("/" + BUCKET, "");
    }

    @Test
    void verifiedPresignedPostDeniedByIdentityPolicy() throws Exception {
        String policy = buildPolicy(BUCKET, KEY, "text/plain", Instant.now().plusSeconds(3600));
        String policyBase64 = Base64.getEncoder().encodeToString(policy.getBytes(StandardCharsets.UTF_8));
        PostSigFields sig = signPost(policyBase64, Instant.now(), playerAccessKeyId, playerSecretAccessKey);

        given()
                .multiPart("key", KEY)
                .multiPart("Content-Type", "text/plain")
                .multiPart("policy", policyBase64)
                .multiPart("x-amz-algorithm", "AWS4-HMAC-SHA256")
                .multiPart("x-amz-credential", sig.credential())
                .multiPart("x-amz-date", sig.amzDate())
                .multiPart("x-amz-signature", sig.signature())
                .multiPart("file", "denied-post.txt", "should not land".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + BUCKET)
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

    private static String buildPolicy(String bucket, String key, String contentType, Instant expiration) {
        String expirationText = expiration.atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
        return """
                {
                  "expiration": "%s",
                  "conditions": [
                    {"bucket": "%s"},
                    {"key": "%s"},
                    {"Content-Type": "%s"},
                    ["content-length-range", 0, 10485760]
                  ]
                }
                """.formatted(expirationText, bucket, key, contentType);
    }

    private static PostSigFields signPost(String policyBase64, Instant when, String accessKeyId, String secret)
            throws Exception {
        String amzDate = AMZ_DATE_FORMAT.format(when);
        String dateStamp = amzDate.substring(0, 8);
        String credential = accessKeyId + "/" + dateStamp + "/" + REGION + "/s3/aws4_request";
        String signature = SigV4RequestValidator.computePresignedPostSignature(
                policyBase64, credential, secret);
        return new PostSigFields(credential, amzDate, signature);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private record PostSigFields(String credential, String amzDate, String signature) {
    }
}
