package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
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
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;

/**
 * Negative regressions for {@link AnonymousAccessGate}: unsigned requests must not bypass
 * strict IAM unless the destination explicitly permits anonymous access.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AnonymousAccessGateBypassIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String PRIVATE_BUCKET = "private-gate-deny-bucket";
    private static final String PUBLIC_READ_BUCKET = "public-read-put-deny-bucket";
    private static final String OBJECT_KEY = "object.txt";
    private static final String OBJECT_BODY = "gate bypass probe body";
    private static final String IAM_APIGW_API = "iam-auth-gate-api";
    private static final String IAM_URL_FUNCTION = "iam-url-gate-fn";
    private static final String NONE_NO_POLICY_FUNCTION = "none-no-policy-gate-fn";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    S3Service s3Service;

    private String hostHeader;
    private String iamApigwApiId;
    private String iamLambdaUrlId;
    private String noneNoPolicyUrlId;

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        provisionPrivateS3Bucket();
        provisionPublicReadS3Bucket();
        provisionIamAuthApiGateway();
        provisionIamAuthLambdaUrl();
        provisionNoneAuthLambdaUrlWithoutPolicy();
    }

    @Test
    void unsignedGetObjectDeniedOnPrivateBucket() {
        given()
        .when()
                .get("/" + PRIVATE_BUCKET + "/" + OBJECT_KEY)
        .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("MissingAuthentication"),
                        containsString("AccessDenied")));
    }

    @Test
    void unsignedPutObjectDeniedDespitePublicGetObjectPolicy() {
        given()
                .contentType("text/plain")
                .body("unsigned put attempt")
        .when()
                .put("/" + PUBLIC_READ_BUCKET + "/" + OBJECT_KEY)
        .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("MissingAuthentication"),
                        containsString("AccessDenied")));
    }

    @Test
    void unsignedUserRequestInvokeDeniedWithAuthorizationTypeAwsIam() {
        given()
        .when()
                .get("/restapis/" + iamApigwApiId + "/prod/_user_request_/probe")
        .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("MissingAuthentication"),
                        containsString("AccessDenied")));
    }

    @Test
    void unsignedFunctionUrlGetDeniedWithAuthTypeAwsIam() {
        given()
        .when()
                .get("/lambda-url/" + iamLambdaUrlId + "/")
        .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("MissingAuthentication"),
                        containsString("AccessDenied")));
    }

    @Test
    void unsignedFunctionUrlGetDeniedWithAuthTypeNoneButNoPublicResourcePolicy() {
        given()
        .when()
                .get("/lambda-url/" + noneNoPolicyUrlId + "/")
        .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("MissingAuthentication"),
                        containsString("AccessDenied")));
    }

    private void provisionPrivateS3Bucket() throws Exception {
        signedS3Put("/" + PRIVATE_BUCKET, "");
        signedS3Put("/" + PRIVATE_BUCKET + "/" + OBJECT_KEY, OBJECT_BODY);
    }

    private void provisionPublicReadS3Bucket() throws Exception {
        signedS3Put("/" + PUBLIC_READ_BUCKET, "");
        signedS3Put("/" + PUBLIC_READ_BUCKET + "/" + OBJECT_KEY, OBJECT_BODY);

        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":"*","Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::%s/*"}
            ]}""".formatted(PUBLIC_READ_BUCKET);
        s3Service.putBucketPolicy(PUBLIC_READ_BUCKET, bucketPolicy);
    }

    private void provisionIamAuthApiGateway() throws Exception {
        iamApigwApiId = signedJsonPost("/restapis", """
                {"name":"%s"}""".formatted(IAM_APIGW_API))
                .extract().path("id");

        String rootId = signedJsonGet("/restapis/" + iamApigwApiId + "/resources")
                .extract().path("item[0].id");

        String resourceId = signedJsonPost("/restapis/" + iamApigwApiId + "/resources/" + rootId, """
                {"pathPart":"probe"}""")
                .extract().path("id");

        signedJsonPut("/restapis/" + iamApigwApiId + "/resources/" + resourceId + "/methods/GET", """
                {"authorizationType":"AWS_IAM"}""");

        signedJsonPut("/restapis/" + iamApigwApiId + "/resources/" + resourceId + "/methods/GET/responses/200", """
                {"responseParameters":{}}""");

        signedJsonPut("/restapis/" + iamApigwApiId + "/resources/" + resourceId + "/methods/GET/integration", """
                {"type":"MOCK","requestTemplates":{"application/json":"{\\"statusCode\\": 200}"}}""");

        signedJsonPut(
                "/restapis/" + iamApigwApiId + "/resources/" + resourceId + "/methods/GET/integration/responses/200",
                """
                {"selectionPattern":"","responseTemplates":{"application/json":"{\\"ok\\":true}"}}""");

        String deploymentId = signedJsonPost("/restapis/" + iamApigwApiId + "/deployments", """
                {"description":"iam-auth-gate-test"}""")
                .extract().path("id");

        signedJsonPost("/restapis/" + iamApigwApiId + "/stages", """
                {"stageName":"prod","deploymentId":"%s"}""".formatted(deploymentId));
    }

    private void provisionIamAuthLambdaUrl() throws Exception {
        String zipBase64 = Base64.getEncoder().encodeToString(minimalZip());
        signedLambdaJsonPost("/2015-03-31/functions", """
                {
                  "FunctionName": "%s",
                  "Runtime": "nodejs20.x",
                  "Role": "arn:aws:iam::000000000000:role/lambda-role",
                  "Handler": "index.handler",
                  "Code": { "ZipFile": "%s" }
                }
                """.formatted(IAM_URL_FUNCTION, zipBase64));

        String functionUrl = signedLambdaJsonPost("/2021-10-31/functions/" + IAM_URL_FUNCTION + "/url", """
                {"AuthType":"AWS_IAM"}""")
                .extract().path("FunctionUrl");

        iamLambdaUrlId = extractUrlId(functionUrl);
    }

    private void provisionNoneAuthLambdaUrlWithoutPolicy() throws Exception {
        String zipBase64 = Base64.getEncoder().encodeToString(minimalZip());
        signedLambdaJsonPost("/2015-03-31/functions", """
                {
                  "FunctionName": "%s",
                  "Runtime": "nodejs20.x",
                  "Role": "arn:aws:iam::000000000000:role/lambda-role",
                  "Handler": "index.handler",
                  "Code": { "ZipFile": "%s" }
                }
                """.formatted(NONE_NO_POLICY_FUNCTION, zipBase64));

        String functionUrl = signedLambdaJsonPost("/2021-10-31/functions/" + NONE_NO_POLICY_FUNCTION + "/url", """
                {"AuthType":"NONE"}""")
                .extract().path("FunctionUrl");

        noneNoPolicyUrlId = extractUrlId(functionUrl);
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

    private io.restassured.response.ValidatableResponse signedJsonPost(String path, String body) throws Exception {
        return applyApigwSignedRest(SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "apigateway",
                Instant.now()))
                .body(body)
        .when()
                .post(path)
        .then()
                .statusCode(201);
    }

    private io.restassured.response.ValidatableResponse signedJsonPut(String path, String body) throws Exception {
        return applyApigwSignedRest(SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "apigateway",
                Instant.now()))
                .body(body)
        .when()
                .put(path)
        .then();
    }

    private io.restassured.response.ValidatableResponse signedJsonGet(String path) throws Exception {
        return applyApigwSignedRest(SigV4HttpTestSupport.signRestGet(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "apigateway",
                Instant.now()))
        .when()
                .get(path)
        .then()
                .statusCode(200);
    }

    private io.restassured.response.ValidatableResponse signedLambdaJsonPost(String path, String body) throws Exception {
        return applyLambdaSignedRest(SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "lambda",
                Instant.now()))
                .body(body)
        .when()
                .post(path)
        .then()
                .statusCode(201);
    }

    private io.restassured.specification.RequestSpecification applyApigwSignedRest(
            SigV4HttpTestSupport.SignedRestHeaders signed) {
        return given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/json");
    }

    private io.restassured.specification.RequestSpecification applyLambdaSignedRest(
            SigV4HttpTestSupport.SignedRestHeaders signed) {
        return given()
                .header("Host", hostHeader)
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/json");
    }

    private static byte[] minimalZip() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            zos.putNextEntry(new ZipEntry("index.js"));
            zos.write("""
                    exports.handler = async () => ({
                      statusCode: 200,
                      body: JSON.stringify({ ok: true })
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
}
