package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FederatedTokenParserTest {

    @Test
    void parseWebIdentityTokenBuildsProviderArnAndClaims() {
        String jwt = jwt(Map.of(
                "aud", "my-client-id",
                "sub", "user-123",
                "amr", java.util.List.of("authenticated", "accounts.google.com")));
        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, "accounts.google.com", "111122223333");

        assertNotNull(ctx);
        assertEquals(
                "arn:aws:iam::111122223333:oidc-provider/accounts.google.com",
                ctx.federatedPrincipal());
        assertEquals("my-client-id", ctx.conditionClaims().get("aud"));
        assertEquals("user-123", ctx.conditionClaims().get("sub"));
        assertEquals("my-client-id", ctx.conditionClaims().get("accounts.google.com:aud"));
        assertEquals("user-123", ctx.conditionClaims().get("accounts.google.com:sub"));
        assertTrue(ctx.conditionClaims().get("amr").contains("authenticated"));
    }

    @Test
    void parseSamlAssertionExtractsIssuerSubjectAndRecipient() {
        String xml = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject>
                    <saml:NameID>alice@example.com</saml:NameID>
                    <saml:SubjectConfirmation>
                      <saml:SubjectConfirmationData Recipient="https://sts.amazonaws.com"/>
                    </saml:SubjectConfirmation>
                  </saml:Subject>
                </saml:Assertion>""";
        String assertion = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        String principalArn = "arn:aws:iam::111122223333:saml-provider/CorpIdP";

        FederatedTrustContext ctx = FederatedTokenParser.parseSamlAssertion(
                assertion, principalArn);

        assertNotNull(ctx);
        assertEquals(principalArn, ctx.federatedPrincipal());
        assertEquals("https://idp.example.com", ctx.conditionClaims().get("saml:iss"));
        assertEquals("alice@example.com", ctx.conditionClaims().get("saml:sub"));
        assertEquals("https://sts.amazonaws.com", ctx.conditionClaims().get("saml:aud"));
        assertEquals("111122223333/CorpIdP", ctx.conditionClaims().get("saml:doc"));
    }

    @Test
    void resolveOidcProviderPrincipalAcceptsFullArn() {
        String arn = "arn:aws:iam::999988887777:oidc-provider/token.actions.githubusercontent.com";
        assertEquals(arn, FederatedTokenParser.resolveOidcProviderPrincipal(arn, "111122223333"));
    }

    @Test
    void malformedJwtReturnsNullContext() {
        assertTrue(FederatedTokenParser.parseJwtPayload("not-a-jwt").isEmpty());
        assertNull(FederatedTokenParser.parseWebIdentityToken(
                "not-a-jwt", "accounts.google.com", "111122223333"));
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
