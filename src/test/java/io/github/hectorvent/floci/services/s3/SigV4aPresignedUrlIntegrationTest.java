package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.SigV4aPresignSupport;
import io.github.hectorvent.floci.core.common.SigV4aTestSupport;
import io.github.hectorvent.floci.services.s3.PreSignedUrlGenerator;
import io.github.hectorvent.floci.testsupport.SigV4aValidationProfile;
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

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
@TestProfile(SigV4aValidationProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SigV4aPresignedUrlIntegrationTest {

    private static final String BUCKET = "sigv4a-presign-bucket";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    PreSignedUrlGenerator presignGenerator;

    @BeforeAll
    void bindRestAssured() {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();
    }

    @Test
    @Order(1)
    void createBucketAndObject() {
        given().when().put("/" + BUCKET).then().statusCode(200);
        given()
            .body("sigv4a content")
            .contentType("text/plain")
        .when()
            .put("/" + BUCKET + "/object.txt")
        .then()
            .statusCode(200);
    }

    @Test
    @Order(2)
    void validSigV4aPresignedGetUrlSucceeds() {
        String baseUrl = endpoint.toString().replaceAll("/$", "");
        String presignedUrl = presignGenerator.generateSigV4aPresignedUrl(
                baseUrl,
                BUCKET,
                "object.txt",
                "GET",
                3600,
                SigV4aTestSupport.ACCESS_KEY_ID,
                SigV4aTestSupport.privateKey());
        String hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
        String pathAndQuery = presignedUrl.substring(baseUrl.length());

        given()
            .urlEncodingEnabled(false)
            .header("Host", hostHeader)
        .when()
            .get(pathAndQuery)
        .then()
            .statusCode(200)
            .body(equalTo("sigv4a content"));
    }

    @Test
    @Order(3)
    void tamperedSigV4aPresignedUrlRejected() {
        String baseUrl = endpoint.toString().replaceAll("/$", "");
        String presignedUrl = presignGenerator.generateSigV4aPresignedUrl(
                baseUrl,
                BUCKET,
                "object.txt",
                "GET",
                3600,
                SigV4aTestSupport.ACCESS_KEY_ID,
                SigV4aTestSupport.privateKey());
        String pathAndQuery = presignedUrl.substring(baseUrl.length())
                .replaceAll("X-Amz-Signature=[0-9a-f]+", "X-Amz-Signature=deadbeef");
        String hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        given()
            .urlEncodingEnabled(false)
            .header("Host", hostHeader)
        .when()
            .get(pathAndQuery)
        .then()
            .statusCode(403)
            .body(containsString("SignatureDoesNotMatch"));
    }

    @Test
    @Order(99)
    void cleanup() {
        given().when().delete("/" + BUCKET + "/object.txt").then().statusCode(204);
        given().when().delete("/" + BUCKET).then().statusCode(204);
    }
}
