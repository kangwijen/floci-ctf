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
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;

/**
 * Regression: Credential-smuggling must not skip SigV4 when validate-signatures is on.
 *
 * <p>Headers that carry {@code Credential=} without the exact {@code AWS4-HMAC-SHA256}
 * prefix (or with a case-variant algorithm) must be rejected before operator-root IAM bypass.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SigV4CredentialSmugglingBypassIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String FORM_BODY = "Action=GetCallerIdentity";
    private static final String SMUGGLED_CREDENTIAL =
            "Credential=" + ROOT_ACCESS_KEY_ID + "/20260712/" + REGION + "/sts/aws4_request";

    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;

    @BeforeAll
    void bind() {
        io.restassured.RestAssured.baseURI = endpoint.toString();
        io.restassured.RestAssured.port = endpoint.getPort();
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();
    }

    @Test
    void rootCredentialWithoutAws4PrefixDenied() {
        given()
                .header("Host", hostHeader)
                .header("Authorization", SMUGGLED_CREDENTIAL)
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(FORM_BODY)
                .when().post("/")
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("IncompleteSignature"),
                        containsString("SignatureDoesNotMatch"),
                        containsString("InvalidClientTokenId"),
                        containsString("AccessDenied"),
                        containsString("MissingAuthentication")));
    }

    @Test
    void lowercaseAws4AlgorithmPrefixDenied() {
        given()
                .header("Host", hostHeader)
                .header("Authorization", "aws4-hmac-sha256 " + SMUGGLED_CREDENTIAL)
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(FORM_BODY)
                .when().post("/")
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("IncompleteSignature"),
                        containsString("SignatureDoesNotMatch"),
                        containsString("InvalidClientTokenId"),
                        containsString("AccessDenied"),
                        containsString("MissingAuthentication")));
    }

    @Test
    void properlySignedRootSucceeds() throws Exception {
        SigV4HttpTestSupport.SignedHeaders signed = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "sts",
                FORM_BODY,
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(FORM_BODY)
                .when().post("/")
                .then()
                .statusCode(200)
                .body(anyOf(
                        containsString("GetCallerIdentityResponse"),
                        containsString("Account")));
    }

    @Test
    void controlProperAws4PrefixWithWrongSignatureDenied() throws Exception {
        SigV4HttpTestSupport.SignedHeaders signed = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                "wrong-secret-32chars!!!!!!!!!!!!!!",
                REGION,
                "sts",
                FORM_BODY,
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(FORM_BODY)
                .when().post("/")
                .then()
                .statusCode(403);
    }
}
