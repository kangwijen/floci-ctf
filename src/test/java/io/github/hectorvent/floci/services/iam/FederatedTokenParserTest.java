package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FederatedTokenParserTest {

    private static final String PROVIDER_HOST = "accounts.google.com";
    private static final FederatedTokenValidationConfig STRUCTURAL_ONLY =
            new FederatedTokenValidationConfig(true, Optional.empty(), Map.of(), Optional.empty());

    @Test
    void parseWebIdentityTokenBuildsProviderArnAndClaims() {
        String jwt = jwt(Map.of(
                "aud", "my-client-id",
                "sub", "user-123",
                "amr", java.util.List.of("authenticated", "accounts.google.com")));
        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333");

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
    void buildOidcConditionClaimsMapsAllScalarTopLevelClaims() {
        Map<String, Object> claims = Map.of(
                "aud", "my-client-id",
                "sub", "user-123",
                "email", "player@example.com",
                "email_verified", true,
                "exp", 9999999999L);
        Map<String, String> conditionClaims = FederatedTokenParser.buildOidcConditionClaims(
                claims, PROVIDER_HOST);

        assertEquals("player@example.com", conditionClaims.get(PROVIDER_HOST + ":email"));
        assertEquals("true", conditionClaims.get(PROVIDER_HOST + ":email_verified"));
        assertNull(conditionClaims.get(PROVIDER_HOST + ":exp"));
        assertEquals("my-client-id", conditionClaims.get(PROVIDER_HOST + ":oaud"));
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
                "not-a-jwt", PROVIDER_HOST, "111122223333"));
    }

    @Test
    void validateFederatedTokensRejectsMalformedJwt() {
        assertFalse(FederatedTokenParser.isStructurallyValidJwt("not-a-jwt"));
        assertNull(FederatedTokenParser.parseWebIdentityToken(
                "not-a-jwt", PROVIDER_HOST, "111122223333", true));
    }

    @Test
    void validateFederatedTokensRejectsExpiredJwt() {
        long expired = java.time.Instant.now().getEpochSecond() - 60;
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user", "exp", expired), "secret");
        assertTrue(FederatedTokenParser.isJwtExpired(Map.of("exp", expired)));
        assertNull(FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", STRUCTURAL_ONLY));
    }

    @Test
    void validateFederatedTokensAcceptsValidUnexpiredJwt() {
        long future = java.time.Instant.now().getEpochSecond() + 3600;
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true, Optional.of("lab-secret"), Map.of(), Optional.empty());
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user", "exp", future), "lab-secret");
        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", config);
        assertNotNull(ctx);
        assertEquals("client", ctx.conditionClaims().get("aud"));
    }

    @Test
    void validateFederatedTokensRejectsAlgNone() {
        long future = java.time.Instant.now().getEpochSecond() + 3600;
        String jwt = jwt(Map.of("aud", "client", "sub", "user", "exp", future));
        assertNull(FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", STRUCTURAL_ONLY));
    }

    @Test
    void parseJwtWhenValidateFederatedTokensDisabledSkipsSignatureVerification() {
        long expired = java.time.Instant.now().getEpochSecond() - 60;
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user", "exp", expired), "wrong-secret");

        assertNull(FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", STRUCTURAL_ONLY));

        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", FederatedTokenValidationConfig.disabled());
        assertNotNull(ctx);
        assertEquals("client", ctx.conditionClaims().get("aud"));
        assertEquals("user", ctx.conditionClaims().get("sub"));

        FederatedTrustContext booleanOff = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", false);
        assertNotNull(booleanOff);
        assertEquals("client", booleanOff.conditionClaims().get("aud"));
    }

    @Test
    void validateFederatedTokensRejectsHs256WithoutConfiguredSecret() {
        long future = java.time.Instant.now().getEpochSecond() + 3600;
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user", "exp", future), "secret");
        assertNull(FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", STRUCTURAL_ONLY));
    }

    @Test
    void validateFederatedTokensVerifiesHs256WithPerProviderSecret() throws Exception {
        long future = java.time.Instant.now().getEpochSecond() + 3600;
        String secret = "provider-specific-secret";
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true, Optional.empty(), Map.of(PROVIDER_HOST, secret), Optional.empty());
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user", "exp", future), secret);
        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", config);
        assertNotNull(ctx);
    }

    @Test
    void validateFederatedTokensVerifiesRs256WithConfiguredPem() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        String pem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";
        long future = java.time.Instant.now().getEpochSecond() + 3600;
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true, Optional.empty(), Map.of(), Optional.of(pem));
        String jwt = rs256Jwt(Map.of("aud", "client", "sub", "user", "exp", future), keyPair);
        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", config);
        assertNotNull(ctx);
    }

    @Test
    void validateFederatedTokensRejectsMalformedSaml() {
        String badAssertion = Base64.getEncoder().encodeToString("not-xml".getBytes(StandardCharsets.UTF_8));
        assertNull(FederatedTokenParser.parseSamlAssertion(
                badAssertion, "arn:aws:iam::111122223333:saml-provider/CorpIdP", true));
    }

    @Test
    void validateFederatedTokensRejectsSamlWithoutSignature() {
        String xml = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
                </saml:Assertion>""";
        String assertion = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        assertNull(FederatedTokenParser.parseSamlAssertion(
                assertion, "arn:aws:iam::111122223333:saml-provider/CorpIdP", true));
    }

    @Test
    void multiValueAudStoresCommaJoinedInProviderPrefixedKey() {
        java.util.List<String> audiences = java.util.List.of("client-a", "client-b");
        Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("aud", audiences);
        claims.put("sub", "user-xyz");
        Map<String, String> conditionClaims = FederatedTokenParser.buildOidcConditionClaims(
                claims, PROVIDER_HOST);

        String prefixedAud = conditionClaims.get(PROVIDER_HOST + ":aud");
        assertNotNull(prefixedAud);
        assertTrue(prefixedAud.contains("client-a"), "provider-prefixed :aud must include client-a");
        assertTrue(prefixedAud.contains("client-b"), "provider-prefixed :aud must include client-b");
        assertTrue(prefixedAud.contains(","), "provider-prefixed :aud must be comma-joined for multi-value");
        assertEquals("client-a", conditionClaims.get("aud"),
                "non-prefixed aud key keeps first audience");
    }

    @Test
    void multiValueAudAzpTakesPriorityOverCommaJoined() {
        java.util.List<String> audiences = java.util.List.of("client-a", "client-b");
        Map<String, Object> claims = new java.util.LinkedHashMap<>();
        claims.put("aud", audiences);
        claims.put("azp", "authorized-party");
        claims.put("sub", "user-xyz");
        Map<String, String> conditionClaims = FederatedTokenParser.buildOidcConditionClaims(
                claims, PROVIDER_HOST);

        assertEquals("authorized-party", conditionClaims.get(PROVIDER_HOST + ":aud"),
                "when azp is present it overrides comma-joined aud for provider-prefixed key");
        assertEquals("authorized-party", conditionClaims.get("aud"));
    }

    @Test
    void isJwtNotYetValidReturnsTrueForFutureNbf() {
        long futureNbf = java.time.Instant.now().getEpochSecond() + 3600;
        assertTrue(FederatedTokenParser.isJwtNotYetValid(Map.of("nbf", futureNbf)));
    }

    @Test
    void isJwtNotYetValidReturnsFalseForPastNbf() {
        long pastNbf = java.time.Instant.now().getEpochSecond() - 60;
        assertFalse(FederatedTokenParser.isJwtNotYetValid(Map.of("nbf", pastNbf)));
    }

    @Test
    void isJwtNotYetValidReturnsFalseWhenNbfAbsent() {
        assertFalse(FederatedTokenParser.isJwtNotYetValid(Map.of("sub", "user")));
    }

    @Test
    void validateFederatedTokensRejectsJwtWithFutureNbf() {
        long futureNbf = java.time.Instant.now().getEpochSecond() + 3600;
        long futureExp = java.time.Instant.now().getEpochSecond() + 7200;
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user",
                "exp", futureExp, "nbf", futureNbf), "lab-secret");
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true, Optional.of("lab-secret"), Map.of(), Optional.empty());
        assertNull(FederatedTokenParser.parseWebIdentityToken(jwt, PROVIDER_HOST, "111122223333", config),
                "token with nbf in the future must be rejected");
    }

    @Test
    void validateFederatedTokensAcceptsJwtWithPastNbf() {
        long pastNbf = java.time.Instant.now().getEpochSecond() - 60;
        long futureExp = java.time.Instant.now().getEpochSecond() + 3600;
        String jwt = hs256Jwt(Map.of("aud", "client", "sub", "user",
                "exp", futureExp, "nbf", pastNbf), "lab-secret");
        FederatedTokenValidationConfig config = new FederatedTokenValidationConfig(
                true, Optional.of("lab-secret"), Map.of(), Optional.empty());
        FederatedTrustContext ctx = FederatedTokenParser.parseWebIdentityToken(
                jwt, PROVIDER_HOST, "111122223333", config);
        assertNotNull(ctx, "token with past nbf must be accepted");
    }

    @Test
    void validateFederatedTokensRejectsSamlWithTrivialSignatureValue() {
        String shortSig = Base64.getEncoder().encodeToString(new byte[8]);
        String xml = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
                  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:SignedInfo>
                      <ds:DigestValue>dGVzdA==</ds:DigestValue>
                    </ds:SignedInfo>
                    <ds:SignatureValue>%s</ds:SignatureValue>
                  </ds:Signature>
                </saml:Assertion>""".formatted(shortSig);
        String assertion = Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        assertNull(FederatedTokenParser.parseSamlAssertion(
                assertion, "arn:aws:iam::111122223333:saml-provider/CorpIdP", true),
                "SAML with SignatureValue shorter than 64 bytes decoded must be rejected");
    }

    @Test
    void validateFederatedTokensAcceptsSamlWithAdequateSignatureValue() {
        byte[] sigBytes = new byte[128];
        new java.security.SecureRandom().nextBytes(sigBytes);
        String longSig = Base64.getEncoder().encodeToString(sigBytes);
        String xml = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
                  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:SignedInfo>
                      <ds:DigestValue>dGVzdA==</ds:DigestValue>
                    </ds:SignedInfo>
                    <ds:SignatureValue>%s</ds:SignatureValue>
                  </ds:Signature>
                </saml:Assertion>""".formatted(longSig);
        String assertion = Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        FederatedTrustContext ctx = FederatedTokenParser.parseSamlAssertion(
                assertion, "arn:aws:iam::111122223333:saml-provider/CorpIdP", true);
        assertNotNull(ctx, "SAML with SignatureValue >= 64 bytes decoded must be accepted");
        assertEquals("alice@example.com", ctx.conditionClaims().get("saml:sub"));
    }

    @Test
    void validateFederatedTokensRejectsSamlWithDigestOnlySignature() {
        String xml = """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
                  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:SignedInfo>
                      <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                      <ds:DigestValue>dGVzdA==</ds:DigestValue>
                    </ds:SignedInfo>
                  </ds:Signature>
                </saml:Assertion>""";
        String assertion = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
        assertNull(FederatedTokenParser.parseSamlAssertion(
                assertion, "arn:aws:iam::111122223333:saml-provider/CorpIdP", true),
                "SAML with DigestValue but no SignatureValue must be rejected when validation is on");
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

    private static String rs256Jwt(Map<String, Object> claims, KeyPair keyPair) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String header = base64Url("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"test\"}");
        String payload = base64Url(mapper.writeValueAsString(claims));
        String signingInput = header + "." + payload;
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + base64UrlBytes(signature.sign());
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String base64UrlBytes(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
