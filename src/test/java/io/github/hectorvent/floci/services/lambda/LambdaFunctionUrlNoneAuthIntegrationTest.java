package io.github.hectorvent.floci.services.lambda;

import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.ByteArrayOutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
/**
 * Lambda function URL {@code AuthType=NONE} with a public resource policy allows unsigned GET
 * under IAM strict enforcement via {@link io.github.hectorvent.floci.core.common.AnonymousAccessGate}.
 *
 * <p>{@code AnonymousAccessGate} requires both {@code AuthType=NONE} and a function resource policy
 * that allows {@code lambda:InvokeFunctionUrl} for anonymous principals.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LambdaFunctionUrlNoneAuthIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String SERVICE = "lambda";
    private static final String FUNCTION = "anonymous-url-fn";
    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;
    private String urlId;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        String zipBase64 = Base64.getEncoder().encodeToString(minimalZip());
        signedJsonPost("/2015-03-31/functions", """
                {
                  "FunctionName": "%s",
                  "Runtime": "nodejs20.x",
                  "Role": "arn:aws:iam::000000000000:role/lambda-role",
                  "Handler": "index.handler",
                  "Code": { "ZipFile": "%s" }
                }
                """.formatted(FUNCTION, zipBase64));

        String functionUrl = signedJsonPost("/2021-10-31/functions/" + FUNCTION + "/url", """
                {"AuthType":"NONE"}""")
                .extract().path("FunctionUrl");

        urlId = extractUrlId(functionUrl);

        signedJsonPost("/2015-03-31/functions/" + FUNCTION + "/policy", """
                {
                  "StatementId": "allow-anonymous-url",
                  "Action": "lambda:InvokeFunctionUrl",
                  "Principal": "*",
                  "FunctionUrlAuthType": "NONE"
                }""");
    }

    @Test
    void unsignedFunctionUrlGetSucceedsWithAuthTypeNone() {
        given()
        .when()
                .get("/lambda-url/" + urlId + "/")
        .then()
                .statusCode(200);
    }

    private static byte[] minimalZip() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("index.js"));
            zos.write("""
                    exports.handler = async () => ({
                      statusCode: 200,
                      body: JSON.stringify({ anonymous: true })
                    });
                    """.getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return baos.toByteArray();
    }

    private static String extractUrlId(String functionUrl) {
        String withoutScheme = functionUrl.replaceFirst("^https?://", "");
        int dot = withoutScheme.indexOf('.');
        if (dot <= 0) {
            throw new IllegalStateException("Unexpected FunctionUrl shape: " + functionUrl);
        }
        return withoutScheme.substring(0, dot);
    }

    private io.restassured.response.ValidatableResponse signedJsonPost(String path, String body) throws Exception {
        return applySignedRest(SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                SERVICE,
                Instant.now()))
                .body(body)
        .when()
                .post(path)
        .then()
                .statusCode(201);
    }

    private io.restassured.specification.RequestSpecification applySignedRest(
            SigV4HttpTestSupport.SignedRestHeaders signed) {
        return given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/json");
    }
}
