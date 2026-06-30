package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * Public bucket policy {@code Principal *} with {@code s3:GetObject} allows unsigned GET
 * under IAM strict enforcement when {@link io.github.hectorvent.floci.core.common.AnonymousAccessGate}
 * evaluates the resource policy for anonymous callers.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class S3PublicBucketPolicyAnonymousGetIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String BUCKET = "public-anonymous-read-bucket";
    private static final String KEY = "public-object.txt";
    private static final String BODY = "anonymous public read body";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    S3Service s3Service;

    private String hostHeader;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        signedS3Put("/" + BUCKET, "");
        signedS3Put("/" + BUCKET + "/" + KEY, BODY);

        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::%s/*"}
            ]}""".formatted(BUCKET);
        s3Service.putBucketPolicy(BUCKET, bucketPolicy);
    }

    @Test
    void unsignedGetObjectSucceedsWithPublicBucketPolicy() {
        given()
        .when()
                .get("/" + BUCKET + "/" + KEY)
        .then()
                .statusCode(200)
                .body(equalTo(BODY));
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
}
