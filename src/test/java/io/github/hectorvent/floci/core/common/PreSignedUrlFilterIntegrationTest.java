package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.s3.PreSignedUrlGenerator;
import io.github.hectorvent.floci.testsupport.CtfComposeParityProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_ACCESS_KEY_ID;
import static io.github.hectorvent.floci.testsupport.CtfComposeParityProfile.ROOT_SECRET;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * End-to-end {@code PreSignedUrlFilter} behavior under the Compose CTF profile.
 */
@QuarkusTest
@TestProfile(CtfComposeParityProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class PreSignedUrlFilterIntegrationTest {

    private static final String BUCKET = "presign-filter-bucket";
    private static final String KEY = "object.txt";
    private static final String REGION = "us-east-1";
    private static final DateTimeFormatter AMZ_DATE =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    @TestHTTPResource("/")
    URL endpoint;

    private String hostHeader;

    @BeforeAll
    void bind() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        hostHeader = endpoint.getHost() + ":" + endpoint.getPort();

        SigV4HttpTestSupport.SignedRestHeaders bucketPut = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + BUCKET,
                new byte[0],
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
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
                "presign filter object".getBytes(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "s3",
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", objectPut.authorization())
                .header("x-amz-date", objectPut.amzDate())
                .header("x-amz-content-sha256", objectPut.contentSha256())
                .contentType("text/plain")
                .body("presign filter object")
        .when()
                .put("/" + BUCKET + "/" + KEY)
        .then()
                .statusCode(200);
    }

    @Test
    void presignedGetWithUnknownAkiaReturns403() {
        Instant now = Instant.now();
        String amzDate = AMZ_DATE.format(now);
        String dateStamp = amzDate.substring(0, 8);
        String credential = "AKIAUNKNOWN00001/" + dateStamp + "/" + REGION + "/s3/aws4_request";
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=" + urlEncode(credential)
                + "&X-Amz-Date=" + amzDate
                + "&X-Amz-Expires=3600"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=deadbeef";

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
                .when()
                .get("/" + BUCKET + "/" + KEY + "?" + query)
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("Unknown credentials"),
                        containsString("AccessDenied")));
    }

    @Test
    void expiredPresignedGetReturnsRequestExpiredOr403() {
        String query = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
                + "&X-Amz-Credential=" + urlEncode("AKIAUNKNOWN00001/20200101/" + REGION + "/s3/aws4_request")
                + "&X-Amz-Date=20200101T000000Z"
                + "&X-Amz-Expires=1"
                + "&X-Amz-SignedHeaders=host"
                + "&X-Amz-Signature=deadbeef";

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
                .when()
                .get("/" + BUCKET + "/" + KEY + "?" + query)
                .then()
                .statusCode(403)
                .body(anyOf(
                        containsString("Request has expired"),
                        containsString("RequestExpired"),
                        containsString("AccessDenied")));
    }

    @Test
    void presignedGetWithAsiaKeyMissingSessionTokenDenied() throws Exception {
        AsiaCredentials asia = assumeRoleForPresignFilter("presign-filter-asia-role");

        String presignedWithToken = buildPresignedGetUrl(
                KEY,
                asia.accessKeyId(),
                asia.secretAccessKey(),
                asia.sessionToken(),
                true);
        URI uri = URI.create(presignedWithToken);
        String queryWithoutToken = stripQueryParam(uri.getRawQuery(), "X-Amz-Security-Token");

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
        .when()
                .get(uri.getRawPath() + "?" + queryWithoutToken)
        .then()
                .statusCode(403)
                .body(containsString("InvalidClientTokenId"));
    }

    @Test
    void presignedGetWithAsiaKeyAndSessionTokenPassesFilter() throws Exception {
        String objectKey = "asia-presign-object.txt";
        SigV4HttpTestSupport.SignedRestHeaders objectPut = SigV4HttpTestSupport.signRestPut(
                endpoint.getHost(),
                endpoint.getPort(),
                "/" + BUCKET + "/" + objectKey,
                "asia presign body".getBytes(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                null,
                REGION,
                "s3",
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", objectPut.authorization())
                .header("x-amz-date", objectPut.amzDate())
                .header("x-amz-content-sha256", objectPut.contentSha256())
                .contentType("text/plain")
                .body("asia presign body")
        .when()
                .put("/" + BUCKET + "/" + objectKey)
        .then()
                .statusCode(200);

        String roleName = "presign-filter-asia-role-2";
        String s3ReadPolicy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Action":"s3:GetObject",
                  "Resource":"arn:aws:s3:::%s/*"
                }]}""".formatted(BUCKET);

        AsiaCredentials asia = assumeRoleForPresignFilter(roleName, s3ReadPolicy);
        String presignedUrl = buildPresignedGetUrl(
                objectKey,
                asia.accessKeyId(),
                asia.secretAccessKey(),
                asia.sessionToken(),
                true);
        URI uri = URI.create(presignedUrl);

        given()
                .urlEncodingEnabled(false)
                .header("Host", hostHeader)
        .when()
                .get(uri.getRawPath() + "?" + uri.getRawQuery())
        .then()
                .statusCode(200)
                .body(equalTo("asia presign body"));
    }

    private AsiaCredentials assumeRoleForPresignFilter(String roleName) throws Exception {
        return assumeRoleForPresignFilter(roleName, null);
    }

    private AsiaCredentials assumeRoleForPresignFilter(String roleName, String inlinePolicyDocument) throws Exception {
        String trustPolicy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Principal":{"AWS":"arn:aws:iam::000000000000:root"},
                  "Action":"sts:AssumeRole"
                }]}""";

        String createRoleBody = "Action=CreateRole"
                + "&RoleName=" + roleName
                + "&AssumeRolePolicyDocument=" + urlEncode(trustPolicy);
        SigV4HttpTestSupport.SignedHeaders createRoleSigned = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                ROOT_ACCESS_KEY_ID,
                ROOT_SECRET,
                REGION,
                "iam",
                createRoleBody,
                Instant.now());

        given()
                .header("Host", hostHeader)
                .header("Authorization", createRoleSigned.authorization())
                .header("x-amz-date", createRoleSigned.amzDate())
                .header("x-amz-content-sha256", createRoleSigned.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(createRoleBody)
        .when()
                .post("/")
        .then()
                .statusCode(200);

        if (inlinePolicyDocument != null) {
            String putPolicyBody = "Action=PutRolePolicy"
                    + "&RoleName=" + roleName
                    + "&PolicyName=presign-s3-read"
                    + "&PolicyDocument=" + urlEncode(inlinePolicyDocument);
            SigV4HttpTestSupport.SignedHeaders putPolicySigned = SigV4HttpTestSupport.signFormPost(
                    endpoint.getHost(),
                    endpoint.getPort(),
                    ROOT_ACCESS_KEY_ID,
                    ROOT_SECRET,
                    REGION,
                    "iam",
                    putPolicyBody,
                    Instant.now());
            given()
                    .header("Host", hostHeader)
                    .header("Authorization", putPolicySigned.authorization())
                    .header("x-amz-date", putPolicySigned.amzDate())
                    .header("x-amz-content-sha256", putPolicySigned.contentSha256())
                    .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                    .body(putPolicyBody)
            .when()
                    .post("/")
            .then()
                    .statusCode(200);
        }

        String assumeBody = "Action=AssumeRole"
                + "&RoleArn=arn:aws:iam::000000000000:role/" + roleName
                + "&RoleSessionName=presign-filter-session";
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
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract().xmlPath();

        return new AsiaCredentials(
                creds.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId"),
                creds.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SecretAccessKey"),
                creds.getString("AssumeRoleResponse.AssumeRoleResult.Credentials.SessionToken"));
    }

    private String buildPresignedGetUrl(String objectKey,
                                        String accessKeyId,
                                        String secretAccessKey,
                                        String sessionToken,
                                        boolean includeSessionToken) throws Exception {
        Instant now = Instant.now();
        String amzDate = AMZ_DATE.format(now);
        String dateStamp = amzDate.substring(0, 8);
        String credentialScope = dateStamp + "/" + REGION + "/s3/aws4_request";
        String credentialValue = accessKeyId + "/" + credentialScope;

        java.util.Map<String, String> extraParams = new java.util.LinkedHashMap<>();
        if (includeSessionToken && sessionToken != null && !sessionToken.isBlank()) {
            extraParams.put("X-Amz-Security-Token", sessionToken);
        }
        String signedHeaders = PreSignedUrlGenerator.buildPresignedSignedHeaders(extraParams);
        String rawPath = "/" + BUCKET + "/" + objectKey;
        String rawQueryWithoutSignature = PreSignedUrlGenerator.buildPresignQueryWithoutSignature(
                credentialValue, amzDate, 3600, signedHeaders, extraParams);

        String signature = io.github.hectorvent.floci.core.common.SigV4RequestValidator.computePresignedSignature(
                "GET",
                rawPath,
                rawQueryWithoutSignature,
                hostHeader,
                secretAccessKey,
                amzDate,
                signedHeaders,
                REGION,
                "s3",
                dateStamp,
                credentialScope);

        return rawPath + "?" + rawQueryWithoutSignature + "&X-Amz-Signature=" + signature;
    }

    private static String stripQueryParam(String rawQuery, String paramName) {
        StringBuilder stripped = new StringBuilder();
        for (String part : rawQuery.split("&")) {
            if (part.isEmpty()) {
                continue;
            }
            int eq = part.indexOf('=');
            String name = eq >= 0 ? part.substring(0, eq) : part;
            if (paramName.equalsIgnoreCase(name)) {
                continue;
            }
            if (!stripped.isEmpty()) {
                stripped.append('&');
            }
            stripped.append(part);
        }
        return stripped.toString();
    }

    private record AsiaCredentials(String accessKeyId, String secretAccessKey, String sessionToken) {}

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
