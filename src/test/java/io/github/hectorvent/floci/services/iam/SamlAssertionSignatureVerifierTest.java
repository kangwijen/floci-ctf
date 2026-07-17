package io.github.hectorvent.floci.services.iam;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("security-regression")
class SamlAssertionSignatureVerifierTest {

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
    void verifyAcceptsSignedAssertionWithPinnedCertificate() {
        assertTrue(SamlAssertionSignatureVerifier.verify(
                signedAssertionXml,
                List.of(signingMaterial.certificatePem())));
    }

    @Test
    void verifyRejectsAssertionSignedWithDifferentKey() throws Exception {
        SamlAssertionTestSupport.SigningMaterial other = SamlAssertionTestSupport.generateSigningMaterial();
        String otherSigned = SamlAssertionTestSupport.signAssertion(
                SamlAssertionTestSupport.baseAssertionXml("alice@example.com"),
                other.certificate(),
                other.keyPair().getPrivate());
        assertFalse(SamlAssertionSignatureVerifier.verify(
                otherSigned,
                List.of(signingMaterial.certificatePem())));
    }

    @Test
    void verifyRejectsUnsignedAssertion() {
        String unsigned = SamlAssertionTestSupport.baseAssertionXml("alice@example.com");
        assertFalse(SamlAssertionSignatureVerifier.verify(
                unsigned,
                List.of(signingMaterial.certificatePem())));
    }

    @Test
    void verifyRejectsWhenNoTrustAnchorsConfigured() {
        assertFalse(SamlAssertionSignatureVerifier.verify(signedAssertionXml, List.of()));
    }

    @Test
    void verifyRejectsAssertionWithDoctypeEntityExpansion() {
        String bomb = """
                <?xml version="1.0"?>
                <!DOCTYPE lolz [
                  <!ENTITY lol "lol">
                  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
                  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
                ]>
                <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
                  <Issuer>&lol3;</Issuer>
                  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                    <SignedInfo/>
                    <SignatureValue>AAA</SignatureValue>
                    <DigestValue>BBB</DigestValue>
                  </Signature>
                </Assertion>
                """;
        assertFalse(SamlAssertionSignatureVerifier.verify(
                bomb,
                List.of(signingMaterial.certificatePem())));
    }

    @Test
    void federatedParserAcceptsSignedAssertionWhenCertConfigured() {
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true,
                Optional.empty(),
                Map.of(),
                Optional.empty(),
                Optional.of(signingMaterial.certificatePem()),
                Map.of());
        String assertion = Base64.getEncoder().encodeToString(signedAssertionXml.getBytes(StandardCharsets.UTF_8));
        FederatedTrustContext ctx = FederatedTokenParser.parseSamlAssertion(
                assertion,
                "arn:aws:iam::111122223333:saml-provider/CorpIdP",
                config);
        assertTrue(ctx != null && "alice@example.com".equals(ctx.conditionClaims().get("saml:sub")));
    }
}
