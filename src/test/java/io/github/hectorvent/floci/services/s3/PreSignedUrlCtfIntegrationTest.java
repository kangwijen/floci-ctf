package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URI;
import java.net.URL;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PreSignedUrlCtfIntegrationTest {

    private static final String BUCKET = "presign-get-bucket";
    private static final String KEY = "object.txt";
    private static final String BODY = "presigned under compose profile";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    PreSignedUrlGenerator presignGenerator;

    @BeforeAll
    void bind() {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();
    }

    @Test
    @Order(1)
    void createBucketAndObjectWithSignedPut() throws Exception {
        String hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

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

        SigV4HttpTestSupport.SignedRestHeaders objectPut = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + BUCKET + "/" + KEY,
                BODY.getBytes(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                "us-east-1",
                "s3",
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", objectPut.authorization())
                .header("x-amz-date", objectPut.amzDate())
                .header("x-amz-content-sha256", objectPut.contentSha256())
                .contentType("text/plain")
                .body(BODY)
        .when()
                .put("/" + BUCKET + "/" + KEY)
        .then()
                .statusCode(200);

        // Sanity: unsigned GET denied under strict CTF profile
        given()
        .when()
                .get("/" + BUCKET + "/" + KEY)
        .then()
                .statusCode(403);
    }

    @Test
    @Order(2)
    void presignedGetRetrievesObjectWithoutAuthorizationHeader() {
        String baseUrl = endpoint.toString().replaceAll("/$", "");
        String presignedUrl = presignGenerator.generatePresignedUrl(
                baseUrl, BUCKET, KEY, "GET", 3600);
        URI uri = URI.create(presignedUrl);

        given()
                .urlEncodingEnabled(false)
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
        .when()
                .get(uri.getRawPath() + "?" + uri.getRawQuery())
        .then()
                .statusCode(200)
                .body(equalTo(BODY));
    }
}
