package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * Under IAM enforcement plus strict mode, unsigned {@code AssumeRoleWithWebIdentity}
 * tokens are denied (federated crypto required). Filter still allows the form post without SigV4.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class StsWebIdentityStrictUnsignedIntegrationTest {

    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String PROVIDER_ARN =
            "arn:aws:iam::" + ACCOUNT + ":oidc-provider/accounts.google.com";
    private static final String ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/strict-web-id-role";

    @TestHTTPResource("/")
    URL endpoint;

    @BeforeAll
    void provisionRole() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{
                "accounts.google.com:aud":"strict-audience",
                "accounts.google.com:sub":"strict-subject"
              }}
            }]}""".formatted(PROVIDER_ARN);

        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "iam"))
                .formParam("Action", "CreateRole")
                .formParam("RoleName", "strict-web-id-role")
                .formParam("AssumeRolePolicyDocument", trustPolicy)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void assumeRoleWithWebIdentityWithoutSigV4UnderStrictModeDeniesUnsignedToken() {
        String token = jwt(Map.of("aud", "strict-audience", "sub", "strict-subject"));

        given()
                .formParam("Action", "AssumeRoleWithWebIdentity")
                .formParam("RoleArn", ROLE_ARN)
                .formParam("RoleSessionName", "strict-web-session")
                .formParam("ProviderId", "accounts.google.com")
                .formParam("WebIdentityToken", token)
                .when().post("/")
                .then()
                .statusCode(400)
                .body("ErrorResponse.Error.Code", equalTo("InvalidIdentityToken"));
    }

    private static String jwt(Map<String, Object> claims) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String header = base64Url("{\"alg\":\"none\",\"typ\":\"JWT\"}");
            String payload = base64Url(mapper.writeValueAsString(claims));
            return header + "." + payload + ".sig";
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
