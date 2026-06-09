package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CtfComposeParityIntegrationTest {

    @TestHTTPResource("/")
    URL endpoint;

    @BeforeAll
    void bind() {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();
    }

    @Test
    void unsignedStsCallDeniedUnderComposeProfile() {
        given()
                .formParam("Action", "GetCallerIdentity")
                .when().post("/")
                .then().statusCode(403);
    }

    @Test
    void signedOperatorRootCanCallSts() throws Exception {
        String formBody = "Action=GetCallerIdentity";
        SigV4HttpTestSupport.SignedHeaders signed = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                "us-east-1",
                "sts",
                formBody,
                Instant.now());

        String hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
        given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(formBody)
                .when().post("/")
                .then().statusCode(200)
                .body(containsString("GetCallerIdentityResponse"));
    }
}
