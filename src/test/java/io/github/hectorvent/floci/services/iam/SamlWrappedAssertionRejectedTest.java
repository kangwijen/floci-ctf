package io.github.hectorvent.floci.services.iam;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression: XML Signature Wrapping (XSW) must not let an unsigned forged Assertion
 * supply claims when a later Assertion carries a valid signature.
 */
@Tag("security-regression")
class SamlWrappedAssertionRejectedTest {

    private static final String PRINCIPAL_ARN =
            "arn:aws:iam::111122223333:saml-provider/CorpIdP";

    private static SamlAssertionTestSupport.SigningMaterial signingMaterial;
    private static String signedAssertionXml;

    @BeforeAll
    static void setUp() throws Exception {
        signingMaterial = SamlAssertionTestSupport.generateSigningMaterial();
        signedAssertionXml = SamlAssertionTestSupport.signAssertion(
                SamlAssertionTestSupport.baseAssertionXml("alice@example.com"),
                signingMaterial.certificate(),
                signingMaterial.keyPair().getPrivate());
    }

    @Test
    void unsignedForgedAssertionPrependedBeforeSignedAssertionIsRejected() {
        String wrapped = """
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" \
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Assertion ID="_forged" Version="2.0">
                    <saml:Issuer>https://evil.example.com</saml:Issuer>
                    <saml:Subject>
                      <saml:NameID>attacker@evil.com</saml:NameID>
                      <saml:SubjectConfirmation>
                        <saml:SubjectConfirmationData Recipient="https://sts.amazonaws.com"/>
                      </saml:SubjectConfirmation>
                    </saml:Subject>
                  </saml:Assertion>
                  %s
                </samlp:Response>""".formatted(signedAssertionXml);

        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true,
                Optional.empty(),
                Map.of(),
                Optional.empty(),
                Optional.of(signingMaterial.certificatePem()),
                Map.of());
        String assertion = Base64.getEncoder().encodeToString(wrapped.getBytes(StandardCharsets.UTF_8));

        FederatedTrustContext ctx = FederatedTokenParser.parseSamlAssertion(
                assertion, PRINCIPAL_ARN, config);

        assertNull(ctx, "XSW response with unsigned forged Assertion before signed Assertion must fail");
    }

    @Test
    void signedAssertionAloneStillAccepted() {
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true,
                Optional.empty(),
                Map.of(),
                Optional.empty(),
                Optional.of(signingMaterial.certificatePem()),
                Map.of());
        String assertion = Base64.getEncoder().encodeToString(
                signedAssertionXml.getBytes(StandardCharsets.UTF_8));

        FederatedTrustContext ctx = FederatedTokenParser.parseSamlAssertion(
                assertion, PRINCIPAL_ARN, config);

        assertTrue(ctx != null && "alice@example.com".equals(ctx.conditionClaims().get("saml:sub")));
    }
}
