package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasXPath;

@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class S3PresignedPostCtfIntegrationTest {

    private static final String BUCKET = "presigned-post-bucket";
    private static final String REGION = "us-east-1";
    private static final DateTimeFormatter AMZ_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @TestHTTPResource("/")
    URL endpoint;

    @BeforeAll
    void bind() throws Exception {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();

        String hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
        SigV4HttpTestSupport.SignedRestHeaders bucketPut = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + BUCKET,
                new byte[0],
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "s3",
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", bucketPut.authorization())
                .header("x-amz-date", bucketPut.amzDate())
                .header("x-amz-content-sha256", bucketPut.contentSha256())
                .body(new byte[0])
        .when()
                .put("/" + BUCKET)
        .then()
                .statusCode(200);
    }

    @Test
    @Order(10)
    void presignedPostUploadsObjectUnderStrictProfile() throws Exception {
        String key = "uploads/sample-post.txt";
        String fileContent = "strict presigned POST";
        String policy = buildPolicy(BUCKET, key, "text/plain", 0, 10485760, Instant.now().plusSeconds(3600));
        String policyBase64 = Base64.getEncoder().encodeToString(policy.getBytes(StandardCharsets.UTF_8));
        PostSigFields sig = signPost(policyBase64, Instant.now());

        given()
                .multiPart("key", key)
                .multiPart("Content-Type", "text/plain")
                .multiPart("policy", policyBase64)
                .multiPart("x-amz-algorithm", "AWS4-HMAC-SHA256")
                .multiPart("x-amz-credential", sig.credential())
                .multiPart("x-amz-date", sig.amzDate())
                .multiPart("x-amz-signature", sig.signature())
                .multiPart("file", "sample-post.txt", fileContent.getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + BUCKET)
        .then()
                .statusCode(204);

        String hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
        SigV4HttpTestSupport.SignedRestHeaders signedGet = SigV4HttpTestSupport.signRestGet(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + BUCKET + "/" + key,
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "s3",
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", signedGet.authorization())
                .header("x-amz-date", signedGet.amzDate())
                .header("x-amz-content-sha256", signedGet.contentSha256())
        .when()
                .get("/" + BUCKET + "/" + key)
        .then()
                .statusCode(200)
                .body(equalTo(fileContent));
    }

    @Test
    @Order(20)
    void unauthenticatedMultipartBucketPostDeniedUnderStrictProfile() {
        given()
                .multiPart("key", "uploads/no-policy.txt")
                .multiPart("Content-Type", "text/plain")
                .multiPart("file", "no-policy.txt", "blocked".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + BUCKET)
        .then()
                .statusCode(403)
                .contentType("application/xml")
                .body(hasXPath("/Error/Code", equalTo("AccessDenied")));
    }

    @Test
    @Order(30)
    void presignedPostRejectsExpiredPolicy() throws Exception {
        String key = "uploads/expired-policy.txt";
        String policy = buildPolicy(BUCKET, key, "text/plain", 0, 10485760,
                Instant.now().minusSeconds(60));
        String policyBase64 = Base64.getEncoder().encodeToString(policy.getBytes(StandardCharsets.UTF_8));
        PostSigFields sig = signPost(policyBase64, Instant.now());

        given()
                .multiPart("key", key)
                .multiPart("Content-Type", "text/plain")
                .multiPart("policy", policyBase64)
                .multiPart("x-amz-algorithm", "AWS4-HMAC-SHA256")
                .multiPart("x-amz-credential", sig.credential())
                .multiPart("x-amz-date", sig.amzDate())
                .multiPart("x-amz-signature", sig.signature())
                .multiPart("file", "expired-policy.txt", "late".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + BUCKET)
        .then()
                .statusCode(403)
                .contentType("application/xml")
                .body(hasXPath("/Error/Code", equalTo("AccessDenied")))
                .body(hasXPath("/Error/Message", equalTo("Request has expired")));
    }

    @Test
    @Order(40)
    void presignedPostRejectsIncompletePolicyFieldsUnderStrictProfile() {
        given()
                .multiPart("key", "uploads/incomplete.txt")
                .multiPart("Content-Type", "text/plain")
                .multiPart("policy", "dummypolicy")
                .multiPart("file", "incomplete.txt", "data".getBytes(StandardCharsets.UTF_8), "text/plain")
        .when()
                .post("/" + BUCKET)
        .then()
                .statusCode(403)
                .contentType("application/xml")
                .body(hasXPath("/Error/Code", equalTo("AccessDenied")))
                .body(hasXPath("/Error/Message", equalTo("Missing required presigned POST policy fields.")));
    }

    private record PostSigFields(String credential, String amzDate, String signature) {
    }

    private static String buildPolicy(String bucket, String key, String contentType,
                                      long minSize, long maxSize, Instant expiration) {
        String expirationText = expiration.atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
        return """
                {
                  "expiration": "%s",
                  "conditions": [
                    {"bucket": "%s"},
                    {"key": "%s"},
                    {"Content-Type": "%s"},
                    ["content-length-range", %d, %d]
                  ]
                }
                """.formatted(expirationText, bucket, key, contentType, minSize, maxSize);
    }

    private PostSigFields signPost(String policyBase64, Instant when) throws Exception {
        String amzDate = AMZ_DATE_FORMAT.format(when);
        String dateStamp = amzDate.substring(0, 8);
        String credential = ROOT_ACCESS_KEY_ID + "/" + dateStamp + "/" + REGION + "/s3/aws4_request";
        String signature = SigV4RequestValidator.computePresignedPostSignature(
                policyBase64, credential, ROOT_SECRET);
        return new PostSigFields(credential, amzDate, signature);
    }
}
