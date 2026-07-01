package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AssumeRoleTrustPolicyEvaluatorTest {

    private final AssumeRoleTrustPolicyEvaluator evaluator = new AssumeRoleTrustPolicyEvaluator(
            new ObjectMapper(), new IamPolicyEvaluator(new ObjectMapper()));

    private static final String TRUST_WITH_EXTERNAL_ID = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"arn:aws:iam::226767940554:user/ext-a"},
              "Action":"sts:AssumeRole",
              "Condition":{"StringEquals":{"sts:ExternalId":"need-this"}}
            }]}""";

    private static final String CALLER = "arn:aws:iam::226767940554:user/ext-a";

    @Test
    void allowsAssumeRoleWithMatchingExternalId() {
        assertTrue(evaluator.isAssumeRoleTrusted(TRUST_WITH_EXTERNAL_ID, CALLER, "need-this"));
    }

    @Test
    void deniesAssumeRoleWithWrongExternalId() {
        assertFalse(evaluator.isAssumeRoleTrusted(TRUST_WITH_EXTERNAL_ID, CALLER, "WRONG"));
    }

    @Test
    void deniesAssumeRoleWithMissingExternalIdWhenRequired() {
        assertFalse(evaluator.isAssumeRoleTrusted(TRUST_WITH_EXTERNAL_ID, CALLER, null));
    }

    @Test
    void deniesAssumeRoleForWrongPrincipal() {
        assertFalse(evaluator.isAssumeRoleTrusted(
                TRUST_WITH_EXTERNAL_ID,
                "arn:aws:iam::226767940554:user/other",
                "need-this"));
    }

    @Test
    void allowsTrustWithoutExternalIdCondition() {
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"%s"},
              "Action":"sts:AssumeRole"
            }]}""".formatted(CALLER);
        assertTrue(evaluator.isAssumeRoleTrusted(trust, CALLER, null));
    }

    @Test
    void allowsAccountRootPrincipalForAnyUserInAccount() {
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"arn:aws:iam::226767940554:root"},
              "Action":"sts:AssumeRole"
            }]}""";
        assertTrue(evaluator.isAssumeRoleTrusted(trust, CALLER, null));
    }

    @Test
    void matchesTrustActionForAssumeRoleWithWebIdentity() {
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"AWS":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity"
            }]}""".formatted(CALLER);
        assertTrue(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity"));
        assertFalse(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRole"));
    }

    @Test
    void allowsOidcFederatedPrincipalWithMatchingClaims() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":oidc-provider/accounts.google.com";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{
                "accounts.google.com:aud":"my-client-id",
                "accounts.google.com:sub":"user-123"
              }}
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(providerArn, Map.of(
                "accounts.google.com:aud", "my-client-id",
                "accounts.google.com:sub", "user-123",
                "aud", "my-client-id",
                "sub", "user-123"));
        assertTrue(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity", ctx));
    }

    @Test
    void deniesOidcFederatedPrincipalWithWrongSubject() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":oidc-provider/accounts.google.com";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{"accounts.google.com:sub":"expected-sub"}}
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(providerArn, Map.of(
                "accounts.google.com:sub", "other-sub",
                "sub", "other-sub"));
        assertFalse(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity", ctx));
    }

    @Test
    void allowsSamlFederatedPrincipalWithMatchingClaims() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":saml-provider/CorpIdP";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithSAML",
              "Condition":{"StringEquals":{
                "SAML:iss":"https://idp.example.com",
                "SAML:sub":"alice@example.com"
              }}
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(providerArn, Map.of(
                "saml:iss", "https://idp.example.com",
                "saml:sub", "alice@example.com",
                "saml:doc", account + "/CorpIdP"));
        assertTrue(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithSAML", ctx));
    }

    @Test
    void multiValueAudStringEqualsMatchesAnyCommaValue() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":oidc-provider/accounts.google.com";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{"accounts.google.com:aud":"client-b"}}
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(providerArn, Map.of(
                "accounts.google.com:aud", "client-a,client-b",
                "aud", "client-a",
                "sub", "user-xyz"));
        assertTrue(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity", ctx),
                "StringEquals on :aud with comma-joined value must match any individual audience");
    }

    @Test
    void multiValueAudStringEqualsNoMatchWhenNonePresent() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":oidc-provider/accounts.google.com";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{"accounts.google.com:aud":"client-c"}}
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(providerArn, Map.of(
                "accounts.google.com:aud", "client-a,client-b",
                "aud", "client-a",
                "sub", "user-xyz"));
        assertFalse(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity", ctx),
                "StringEquals on :aud must deny when none of the comma values matches");
    }

    @Test
    void singleValueAudWithoutCommaUsesExactMatch() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":oidc-provider/accounts.google.com";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity",
              "Condition":{"StringEquals":{"accounts.google.com:aud":"client-a"}}
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(providerArn, Map.of(
                "accounts.google.com:aud", "client-a",
                "aud", "client-a",
                "sub", "user-xyz"));
        assertTrue(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity", ctx),
                "single-value aud without comma uses exact match");
    }

    @Test
    void deniesMismatchedOidcProviderArn() {
        String account = "226767940554";
        String providerArn = "arn:aws:iam::" + account + ":oidc-provider/accounts.google.com";
        String trust = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow",
              "Principal":{"Federated":"%s"},
              "Action":"sts:AssumeRoleWithWebIdentity"
            }]}""".formatted(providerArn);
        FederatedTrustContext ctx = new FederatedTrustContext(
                "arn:aws:iam::" + account + ":oidc-provider/other.example.com", Map.of());
        assertFalse(evaluator.isAssumeRoleTrusted(
                trust, CALLER, null, "sts:AssumeRoleWithWebIdentity", ctx));
    }
}
