package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;

/**
 * End-to-end SigV4 validation under the Compose CTF profile (IAM + strict + validate-signatures).
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SigV4ValidationFilterIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String WRONG_SECRET = "wrong-secret-32chars!!!!!!!!!!!!!!";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAccessKeyId;
    private String hostHeader;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        String userName = "sigv4-filter-player";
        operatorIamFormPost("Action=CreateUser&UserName=" + userName);

        String createKeyBody = "Action=CreateAccessKey&UserName=" + userName;
        SigV4HttpTestSupport.SignedHeaders createKeySigned = signedIamFormPost(createKeyBody);
        var keyResponse = given()
                .header("Host", hostHeader)
                .header("Authorization", createKeySigned.authorization())
                .header("x-amz-date", createKeySigned.amzDate())
                .header("x-amz-content-sha256", createKeySigned.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(createKeyBody)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath();

        playerAccessKeyId = keyResponse.getString(
                "CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
    }

    @Test
    void listQueuesWithWrongSigningSecretDenied() throws Exception {
        String formBody = "Action=ListQueues";
        SigV4HttpTestSupport.SignedHeaders signed = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                playerAccessKeyId,
                WRONG_SECRET,
                REGION,
                "sqs",
                formBody,
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(formBody)
                .when().post("/")
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("SignatureDoesNotMatch"),
                        containsString("InvalidClientTokenId")));
    }

    @Test
    void listQueuesWithTamperedAuthorizationShapeDenied() {
        given()
                .formParam("Action", "ListQueues")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAccessKeyId, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("SignatureDoesNotMatch"),
                        containsString("InvalidClientTokenId")));
    }

    @Test
    void listQueuesWithAsiaKeyMissingSessionTokenDenied() throws Exception {
        String roleName = "sigv4-session-role";
        String trustPolicy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Principal":{"AWS":"arn:aws:iam::000000000000:root"},
                  "Action":"sts:AssumeRole"
                }]}""";

        operatorIamFormPost("Action=CreateRole"
                + "&RoleName=" + roleName
                + "&AssumeRolePolicyDocument=" + urlEncode(trustPolicy));

        String assumeBody = "Action=AssumeRole"
                + "&RoleArn=arn:aws:iam::000000000000:role/" + roleName
                + "&RoleSessionName=sigv4-filter-session";
        SigV4HttpTestSupport.SignedHeaders assumeSigned = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "sts",
                assumeBody,
                Instant.now());

        var creds = given()
                .header("Host", hostHeader)
                .header("Authorization", assumeSigned.authorization())
                .header("x-amz-date", assumeSigned.amzDate())
                .header("x-amz-content-sha256", assumeSigned.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(assumeBody)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath();

        String asiaAccessKeyId = creds.getString(
                "AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId");
        String asiaSecret = creds.getString(
                "AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey");

        String listBody = "Action=ListQueues";
        SigV4HttpTestSupport.SignedHeaders listSigned = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                asiaAccessKeyId,
                asiaSecret,
                REGION,
                "sqs",
                listBody,
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", listSigned.authorization())
                .header("x-amz-date", listSigned.amzDate())
                .header("x-amz-content-sha256", listSigned.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(listBody)
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("InvalidClientTokenId"));
    }

    private void operatorIamFormPost(String formBody) throws Exception {
        SigV4HttpTestSupport.SignedHeaders signed = signedIamFormPost(formBody);
        given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(formBody)
                .when().post("/")
                .then().statusCode(200);
    }

    private SigV4HttpTestSupport.SignedHeaders signedIamFormPost(String formBody) throws Exception {
        return SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "iam",
                formBody,
                Instant.now());
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
