package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.URL;
import java.time.Instant;
import java.util.Map;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class S3PresignedPutSseIntegrationTest {

    private static final String BUCKET = "presigned-sse-put-bucket";
    private static final String KEY = "sse-object.txt";
    private static final String KMS_KEY_ID =
            "arn:aws:kms:us-east-1:000000000000:key/presign-sse-test-key-id";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    PreSignedUrlGenerator presignGenerator;

    private String hostHeader;
    private String baseUrl;

    @BeforeAll
    void provision() throws Exception {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
        baseUrl = endpoint.toString().replaceAll("/$", "");

        SigV4HttpTestSupport.SignedRestHeaders bucketPut = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + BUCKET,
                new byte[0],
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                "us-east-1",
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
    void presignedPutWithSseQueryParamsStoresEncryptionMetadata() throws Exception {
        Map<String, String> sseParams = Map.of(
                "X-Amz-Server-Side-Encryption", "aws:kms",
                "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", KMS_KEY_ID);

        String presignedUrl = presignGenerator.generatePresignedUrl(
                baseUrl, BUCKET, KEY, "PUT", 3600, sseParams);
        URI uri = URI.create(presignedUrl);

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
                .contentType("text/plain")
                .body("uploaded with presigned SSE query params")
        .when()
                .put(uri.getRawPath() + "?" + uri.getRawQuery())
        .then()
                .statusCode(200)
                .header("ETag", notNullValue())
                .header("x-amz-server-side-encryption", equalTo("aws:kms"))
                .header("x-amz-server-side-encryption-aws-kms-key-id", equalTo(KMS_KEY_ID));

        String presignedGetUrl = presignGenerator.generatePresignedUrl(
                baseUrl, BUCKET, KEY, "GET", 3600);
        URI getUri = URI.create(presignedGetUrl);

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
        .when()
                .get(getUri.getRawPath() + "?" + getUri.getRawQuery())
        .then()
                .statusCode(200)
                .header("x-amz-server-side-encryption", equalTo("aws:kms"))
                .header("x-amz-server-side-encryption-aws-kms-key-id", equalTo(KMS_KEY_ID))
                .body(equalTo("uploaded with presigned SSE query params"));
    }
}
