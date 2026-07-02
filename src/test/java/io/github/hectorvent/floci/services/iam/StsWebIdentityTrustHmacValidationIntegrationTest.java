package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.QuarkusTestProfile;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestProfile(StsWebIdentityTrustHmacValidationIntegrationTest.FederatedHmacValidationProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StsWebIdentityTrustHmacValidationIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/iam/aws4_request";
    private static final String STS_AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/sts/aws4_request";
    private static final String PROVIDER_ARN =
            "arn:aws:iam::" + ACCOUNT + ":oidc-provider/accounts.google.com";
    private static final String HMAC_SECRET = "test-hmac-secret";

    private static String roleArn;

    @Test
    @Order(1)
    void provisionWebIdentityRole() {
        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{
                "accounts.google.com:aud":"my-client-id",
                "accounts.google.com:sub":"user-123"
              }}
            }]}""".formatted(PROVIDER_ARN);

        given()
            .formParam("Action", "CreateRole")
            .formParam("RoleName", "web-id-hmac-role")
            .formParam("AssumeRolePolicyDocument", trustPolicy)
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);

        roleArn = "arn:aws:iam::" + ACCOUNT + ":role/web-id-hmac-role";
    }

    @Test
    @Order(2)
    void assumeRoleWithWebIdentityRejectsUnsignedToken() {
        String token = unsignedJwt(Map.of("aud", "my-client-id", "sub", "user-123"));

        given()
            .formParam("Action", "AssumeRoleWithWebIdentity")
            .formParam("RoleArn", roleArn)
            .formParam("RoleSessionName", "web-session")
            .formParam("ProviderId", "accounts.google.com")
            .formParam("WebIdentityToken", token)
            .header("Authorization", STS_AUTH)
        .when().post("/")
        .then()
            .statusCode(400)
            .body(containsString("InvalidIdentityToken"));
    }

    @Test
    @Order(3)
    void assumeRoleWithWebIdentityAllowsHs256SignedToken() {
        long future = java.time.Instant.now().getEpochSecond() + 3600;
        String token = hs256Jwt(Map.of("aud", "my-client-id", "sub", "user-123", "exp", future), HMAC_SECRET);

        given()
            .formParam("Action", "AssumeRoleWithWebIdentity")
            .formParam("RoleArn", roleArn)
            .formParam("RoleSessionName", "web-session")
            .formParam("ProviderId", "accounts.google.com")
            .formParam("WebIdentityToken", token)
            .header("Authorization", STS_AUTH)
        .when().post("/")
        .then()
            .statusCode(200)
            .body("AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials.AccessKeyId",
                    startsWith("ASIA"))
            .body("AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.SubjectFromWebIdentityToken",
                    org.hamcrest.Matchers.equalTo("user-123"));
    }

    public static final class FederatedHmacValidationProfile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.ctf.validate-federated-tokens", "true",
                    "floci.ctf.federated-jwt-hmac-secret", HMAC_SECRET);
        }
    }

    private static String unsignedJwt(Map<String, Object> claims) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
            String payload = base64Url(mapper.writeValueAsString(claims));
            return header + "." + payload + ".sig";
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String hs256Jwt(Map<String, Object> claims, String secret) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String header = base64Url("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
            String payload = base64Url(mapper.writeValueAsString(claims));
            String signingInput = header + "." + payload;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String signature = base64UrlBytes(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
            return signingInput + "." + signature;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64UrlBytes(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
