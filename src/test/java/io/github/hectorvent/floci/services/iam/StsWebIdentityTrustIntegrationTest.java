package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

@QuarkusTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StsWebIdentityTrustIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/iam/aws4_request";
    private static final String STS_AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/sts/aws4_request";
    private static final String PROVIDER_ARN =
            "arn:aws:iam::" + ACCOUNT + ":oidc-provider/accounts.google.com";

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
            .formParam("RoleName", "web-id-role")
            .formParam("AssumeRolePolicyDocument", trustPolicy)
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);

        roleArn = "arn:aws:iam::" + ACCOUNT + ":role/web-id-role";
    }

    @Test
    @Order(2)
    void assumeRoleWithWebIdentityDeniesWrongSubject() {
        String token = jwt(Map.of("aud", "my-client-id", "sub", "wrong-subject"));

        given()
            .formParam("Action", "AssumeRoleWithWebIdentity")
            .formParam("RoleArn", roleArn)
            .formParam("RoleSessionName", "web-session")
            .formParam("ProviderId", "accounts.google.com")
            .formParam("WebIdentityToken", token)
            .header("Authorization", STS_AUTH)
        .when().post("/")
        .then()
            .statusCode(403)
            .body(containsString("AccessDenied"));
    }

    @Test
    @Order(3)
    void assumeRoleWithWebIdentityAllowsMatchingClaims() {
        String token = jwt(Map.of("aud", "my-client-id", "sub", "user-123"));

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

    @Test
    @Order(4)
    void assumeRoleWithSamlAllowsMatchingTrustPolicy() {
        String samlRoleArn = "arn:aws:iam::" + ACCOUNT + ":role/saml-role";
        String samlProviderArn = "arn:aws:iam::" + ACCOUNT + ":saml-provider/CorpIdP";
        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithSAML",
              "Condition":{"StringEquals":{"SAML:sub":"alice@example.com"}}
            }]}""".formatted(samlProviderArn);

        given()
            .formParam("Action", "CreateRole")
            .formParam("RoleName", "saml-role")
            .formParam("AssumeRolePolicyDocument", trustPolicy)
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);

        String assertion = samlAssertion("alice@example.com");

        given()
            .formParam("Action", "AssumeRoleWithSAML")
            .formParam("RoleArn", samlRoleArn)
            .formParam("PrincipalArn", samlProviderArn)
            .formParam("SAMLAssertion", assertion)
            .header("Authorization", STS_AUTH)
        .when().post("/")
        .then()
            .statusCode(200)
            .body("AssumeRoleWithSAMLResponse.AssumeRoleWithSAMLResult.Credentials.AccessKeyId",
                    startsWith("ASIA"));
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

    private static String samlAssertion(String subject) {
        String xml = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject>
                </saml:Assertion>""".formatted(subject);
        return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
