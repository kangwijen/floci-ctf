package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * Under IAM strict enforcement, {@code AnonymousAccessGate} must allow unsigned GetObject when
 * the object ACL grants public read, even without a public bucket policy. Explicit bucket-policy
 * Deny still wins over public ACL.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class S3PublicAclAnonymousGetIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACL_BUCKET = "public-acl-anonymous-read-bucket";
    private static final String ACL_KEY = "public-acl-object.txt";
    private static final String ACL_BODY = "anonymous acl read body";
    private static final String DENY_BUCKET = "public-acl-bucket-policy-deny";
    private static final String DENY_KEY = "denied-acl-object.txt";
    private static final String DENY_BODY = "acl overridden by deny policy";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    S3Service s3Service;

    private String hostHeader;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        signedS3Put("/" + ACL_BUCKET, "");
        signedS3PutWithAcl("/" + ACL_BUCKET + "/" + ACL_KEY, ACL_BODY, "public-read");

        signedS3Put("/" + DENY_BUCKET, "");
        signedS3PutWithAcl("/" + DENY_BUCKET + "/" + DENY_KEY, DENY_BODY, "public-read");

        String denyPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","Principal":"*","Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::%s/%s"}
            ]}""".formatted(DENY_BUCKET, DENY_KEY);
        s3Service.putBucketPolicy(DENY_BUCKET, denyPolicy);
    }

    @Test
    void unsignedGetObjectSucceedsWithPublicObjectAcl() {
        given()
        .when()
                .get("/" + ACL_BUCKET + "/" + ACL_KEY)
        .then()
                .statusCode(200)
                .body(equalTo(ACL_BODY));
    }

    @Test
    void unsignedGetObjectDeniedWhenBucketPolicyDeniesDespitePublicAcl() {
        given()
        .when()
                .get("/" + DENY_BUCKET + "/" + DENY_KEY)
        .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
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

    private void signedS3PutWithAcl(String path, String body, String cannedAcl) throws Exception {
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

        given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .header("x-amz-acl", cannedAcl)
                .contentType("text/plain")
                .body(body)
        .when()
                .put(path)
        .then()
                .statusCode(200);
    }

}
