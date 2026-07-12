package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyPrincipalMatcherTest {

    private static final String ACCOUNT = "111122223333";
    private static final String ROOT_ARN = "arn:aws:iam::" + ACCOUNT + ":root";
    private static final String USER_ARN = "arn:aws:iam::" + ACCOUNT + ":user/reader";
    private static final String ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/DeployRole";
    private static final String ROLE_SESSION =
            "arn:aws:sts::" + ACCOUNT + ":assumed-role/DeployRole/session-1";
    private static final String PATH_ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/path/DeployRole";
    private static final String PATH_ROLE_SESSION =
            "arn:aws:sts::" + ACCOUNT + ":assumed-role/path/DeployRole/session-1";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void resourcePolicyAccountRootDoesNotMatchIamUser() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ROOT_ARN + "\"}");
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    @Test
    void resourcePolicyAccountIdDoesNotMatchIamUser() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ACCOUNT + "\"}");
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    @Test
    void resourcePolicyAccountRootMatchesRootCaller() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ROOT_ARN + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, ROOT_ARN, ACCOUNT));
    }

    @Test
    void resourcePolicyAccountIdMatchesRootCaller() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ACCOUNT + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, ROOT_ARN, ACCOUNT));
    }

    @Test
    void trustPolicyAccountRootMatchesIamUser() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ROOT_ARN + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    @Test
    void trustPolicyAccountIdMatchesIamUser() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ACCOUNT + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    @Test
    void resourcePolicyMatchesExplicitUserArn() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + USER_ARN + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    @Test
    void resourcePolicyRoleArnMatchesAssumedRoleSession() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ROLE_ARN + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, ROLE_SESSION, ACCOUNT));
    }

    @Test
    void resourcePolicyRoleArnMatchesPathAssumedRoleSession() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + PATH_ROLE_ARN + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, PATH_ROLE_SESSION, ACCOUNT));
    }

    @Test
    void resourcePolicyRoleArnDoesNotMatchDifferentRoleSession() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"" + ROLE_ARN + "\"}");
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null,
                "arn:aws:sts::" + ACCOUNT + ":assumed-role/OtherRole/session-1",
                ACCOUNT));
    }

    @Test
    void notPrincipalAccountIdExcludesIamUserInAccount() throws Exception {
        JsonNode notPrincipal = objectMapper.readTree("{\"AWS\":\"" + ACCOUNT + "\"}");
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                null, notPrincipal, USER_ARN, ACCOUNT));
    }

    @Test
    void notPrincipalUserAllowsOtherUser() throws Exception {
        JsonNode notPrincipal = objectMapper.readTree("{\"AWS\":\"" + USER_ARN + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                null, notPrincipal,
                "arn:aws:iam::" + ACCOUNT + ":user/other",
                ACCOUNT));
    }

    @Test
    void wildcardPrincipalMatchesAnyCaller() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"*\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    @Test
    void servicePrincipalMatchesBareServiceString() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"Service\":\"sns.amazonaws.com\"}");
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, "sns.amazonaws.com", ACCOUNT));
    }

    @Test
    void servicePrincipalMatchesServiceLinkedRoleSession() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"Service\":\"s3.amazonaws.com\"}");
        String serviceSession = "arn:aws:sts::" + ACCOUNT
                + ":assumed-role/aws-service-role/s3.amazonaws.com/AWSServiceRoleForS3/session";
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, serviceSession, ACCOUNT));
    }

    @Test
    void servicePrincipalMatchesSnsServiceLinkedRoleSession() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"Service\":\"sns.amazonaws.com\"}");
        String serviceSession =
                "arn:aws:sts::000000000000:assumed-role/aws-service-role/sns.amazonaws.com/"
                        + "AWSServiceRoleForSNS/session";
        assertTrue(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, serviceSession, "000000000000"));
    }

    @Test
    void servicePrincipalDoesNotMatchUnrelatedUser() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"Service\":\"s3.amazonaws.com\"}");
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT));
    }

    /**
     * Regression (VULN-3): RoleSessionName equal to a service principal must not match
     * Principal.Service. Only aws-service-role path SLRs (or bare service strings) match.
     */
    @Test
    void assumedRoleSessionNameDoesNotMatchServicePrincipal() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"Service\":\"sns.amazonaws.com\"}");
        String confusedSession =
                "arn:aws:sts::000000000000:assumed-role/VictimRole/sns.amazonaws.com";
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, confusedSession, "000000000000"));
    }

    @Test
    void principalAndNotPrincipalTogetherAreInvalid() throws Exception {
        JsonNode principal = objectMapper.readTree("{\"AWS\":\"*\"}");
        JsonNode notPrincipal = objectMapper.readTree("{\"AWS\":\"" + USER_ARN + "\"}");
        assertFalse(PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, notPrincipal, USER_ARN, ACCOUNT));
    }

    @Test
    void matchesAssumedRoleSessionHelper() {
        assertTrue(PolicyPrincipalMatcher.matchesAssumedRoleSession(ROLE_ARN, ROLE_SESSION));
        assertTrue(PolicyPrincipalMatcher.matchesAssumedRoleSession(PATH_ROLE_ARN, PATH_ROLE_SESSION));
        assertFalse(PolicyPrincipalMatcher.matchesAssumedRoleSession(
                ROLE_ARN, "arn:aws:sts::999988887777:assumed-role/DeployRole/session-1"));
    }

    @Test
    void trustPolicyOidcProviderArnMatchesProviderHost() throws Exception {
        String providerArn = "arn:aws:iam::" + ACCOUNT + ":oidc-provider/accounts.google.com";
        JsonNode principal = objectMapper.readTree("{\"Federated\":\"" + providerArn + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                principal, null, null, ACCOUNT, providerArn));
    }

    @Test
    void trustPolicyOidcProviderUrlMatchesProviderArn() throws Exception {
        String providerArn = "arn:aws:iam::" + ACCOUNT + ":oidc-provider/token.actions.githubusercontent.com";
        JsonNode principal = objectMapper.readTree(
                "{\"Federated\":\"token.actions.githubusercontent.com\"}");
        assertTrue(PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                principal, null, null, ACCOUNT, providerArn));
    }

    @Test
    void trustPolicySamlProviderArnMatchesExactPrincipalArn() throws Exception {
        String providerArn = "arn:aws:iam::" + ACCOUNT + ":saml-provider/CorpIdP";
        JsonNode principal = objectMapper.readTree("{\"Federated\":\"" + providerArn + "\"}");
        assertTrue(PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                principal, null, null, ACCOUNT, providerArn));
    }
}
