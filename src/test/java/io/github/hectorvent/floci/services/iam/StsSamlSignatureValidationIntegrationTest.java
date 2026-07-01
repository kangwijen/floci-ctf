package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(StsSamlSignatureValidationIntegrationTest.SamlSignatureValidationProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class StsSamlSignatureValidationIntegrationTest {

    private static final String ACCOUNT = "000000000000";
    private static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/iam/aws4_request";
    private static final String STS_AUTH =
            "AWS4-HMAC-SHA256 Credential=test/20260227/us-east-1/sts/aws4_request";
    private static final String PROVIDER_ARN =
            "arn:aws:iam::" + ACCOUNT + ":saml-provider/CorpIdP";

    private static final SamlAssertionTestSupport.SigningMaterial SIGNING_MATERIAL = loadSigningMaterial();

    private static String roleArn;
    private static String signedAssertion;

    @Inject
    EmulatorConfig emulatorConfig;

    private static SamlAssertionTestSupport.SigningMaterial loadSigningMaterial() {
        try {
            return SamlAssertionTestSupport.loadClasspathSigningMaterial();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Test
    @Order(0)
    void federatedSamlValidationConfigIsLoaded() {
        assertTrue(emulatorConfig.ctf().validateFederatedTokens());
        assertFalse(FederatedTokenValidationConfig.from(emulatorConfig.ctf())
                .resolveSamlSigningCertPems("CorpIdP").isEmpty());
    }

    private static String encodeSignedAssertion(String subject) {
        try {
            String xml = SamlAssertionTestSupport.signAssertion(
                    SamlAssertionTestSupport.baseAssertionXml(subject),
                    SIGNING_MATERIAL.certificate(),
                    SIGNING_MATERIAL.keyPair().getPrivate());
            return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign SAML assertion", e);
        }
    }

    @BeforeEach
    void ensureSignedAssertion() {
        signedAssertion = encodeSignedAssertion("alice@example.com");
    }

    @Test
    @Order(1)
    void provisionSamlRole() {
        String trustPolicy = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithSAML",
              "Condition":{"StringEquals":{"SAML:sub":"alice@example.com"}}
            }]}""".formatted(PROVIDER_ARN);

        given()
            .formParam("Action", "CreateRole")
            .formParam("RoleName", "saml-signature-role")
            .formParam("AssumeRolePolicyDocument", trustPolicy)
            .header("Authorization", AUTH)
        .when().post("/")
        .then().statusCode(200);

        roleArn = "arn:aws:iam::" + ACCOUNT + ":role/saml-signature-role";
    }

    @Test
    @Order(2)
    void parseSignedAssertionWithRuntimeConfig() {
        String xml = new String(Base64.getDecoder().decode(signedAssertion), StandardCharsets.UTF_8);
        FederatedTokenValidationConfig config = FederatedTokenValidationConfig.from(emulatorConfig.ctf());
        assertTrue(SamlAssertionSignatureVerifier.verify(
                xml, List.of(SIGNING_MATERIAL.certificatePem())));
        assertTrue(SamlAssertionSignatureVerifier.verify(
                xml, config.resolveSamlSigningCertPems("CorpIdP")));
        FederatedTrustContext ctx = FederatedTokenParser.parseSamlAssertion(
                signedAssertion, PROVIDER_ARN, config);
        assertTrue(ctx != null && "alice@example.com".equals(ctx.conditionClaims().get("saml:sub")));
    }

    @Test
    @Order(3)
    void assumeRoleWithSamlRejectsUnsignedAssertion() {
        String unsigned = Base64.getEncoder().encodeToString(
                SamlAssertionTestSupport.baseAssertionXml("alice@example.com")
                        .getBytes(StandardCharsets.UTF_8));

        given()
            .formParam("Action", "AssumeRoleWithSAML")
            .formParam("RoleArn", roleArn)
            .formParam("PrincipalArn", PROVIDER_ARN)
            .formParam("SAMLAssertion", unsigned)
            .header("Authorization", STS_AUTH)
        .when().post("/")
        .then()
            .statusCode(400)
            .body(containsString("InvalidIdentityToken"));
    }

    @Test
    @Order(4)
    void assumeRoleWithSamlAllowsSignedAssertion() {
        given()
            .formParam("Action", "AssumeRoleWithSAML")
            .formParam("RoleArn", roleArn)
            .formParam("PrincipalArn", PROVIDER_ARN)
            .formParam("SAMLAssertion", signedAssertion)
            .header("Authorization", STS_AUTH)
        .when().post("/")
        .then()
            .statusCode(200)
            .body("AssumeRoleWithSAMLResponse.AssumeRoleWithSAMLResult.Credentials.AccessKeyId",
                    startsWith("ASIA"))
            .body("AssumeRoleWithSAMLResponse.AssumeRoleWithSAMLResult.Subject",
                    equalTo("alice@example.com"));
    }

    public static final class SamlSignatureValidationProfile implements QuarkusTestProfile {

        private static final String TRUST_ANCHOR_PEM = readTrustAnchorPem();

        @Override
        public Map<String, String> getConfigOverrides() {
            Map<String, String> overrides = new HashMap<>();
            overrides.put("floci.ctf.validate-federated-tokens", "true");
            overrides.put("floci.ctf.federated-saml-signing-cert-pem", TRUST_ANCHOR_PEM);
            overrides.put("floci.ctf.federated-saml-signing-certs.CorpIdP", TRUST_ANCHOR_PEM);
            return overrides;
        }

        private static String readTrustAnchorPem() {
            try (InputStream input = SamlSignatureValidationProfile.class.getResourceAsStream("/saml/idp-signing-cert.pem")) {
                if (input == null) {
                    throw new IllegalStateException("Missing classpath resource /saml/idp-signing-cert.pem");
                }
                return new String(input.readAllBytes(), StandardCharsets.UTF_8);
            } catch (Exception e) {
                throw new ExceptionInInitializerError(e);
            }
        }
    }
}
