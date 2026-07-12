package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.core.common.AwsArnUtils;

/**
 * Matches {@code Principal} and {@code NotPrincipal} blocks in resource-based and trust policy statements.
 */
public final class PolicyPrincipalMatcher {

    private PolicyPrincipalMatcher() {
    }

    /**
     * Principal matching for role trust policies. Account root in {@code Principal.AWS}
     * grants any IAM principal in that account (AWS trust-policy semantics).
     */
    public static boolean matchesTrustPrincipalDimension(JsonNode principalNode,
                                                         JsonNode notPrincipalNode,
                                                         String callerArn,
                                                         String callerAccount) {
        return matchesTrustPrincipalDimension(principalNode, notPrincipalNode, callerArn, callerAccount, null);
    }

    public static boolean matchesTrustPrincipalDimension(JsonNode principalNode,
                                                         JsonNode notPrincipalNode,
                                                         String callerArn,
                                                         String callerAccount,
                                                         String federatedPrincipal) {
        String principalArn = federatedPrincipal != null && !federatedPrincipal.isBlank()
                ? federatedPrincipal
                : callerArn;
        if (principalNode != null && !principalNode.isNull()
                && notPrincipalNode != null && !notPrincipalNode.isNull()) {
            return false;
        }
        if (notPrincipalNode != null && !notPrincipalNode.isNull()) {
            return !matchesTrust(notPrincipalNode, principalArn, callerAccount);
        }
        if (principalNode != null && !principalNode.isNull()) {
            return matchesTrust(principalNode, principalArn, callerAccount);
        }
        return false;
    }

    /**
     * Evaluates the principal dimension of a resource-based policy statement.
     *
     * @param principalNode    {@code Principal} element, or null
     * @param notPrincipalNode {@code NotPrincipal} element, or null
     * @return true when the caller matches the principal dimension per AWS rules
     */
    public static boolean matchesPrincipalDimension(JsonNode principalNode,
                                                    JsonNode notPrincipalNode,
                                                    String callerArn,
                                                    String callerAccount) {
        if (principalNode != null && !principalNode.isNull()
                && notPrincipalNode != null && !notPrincipalNode.isNull()) {
            return false;
        }
        if (notPrincipalNode != null && !notPrincipalNode.isNull()) {
            return !matchesResourcePrincipalBlock(notPrincipalNode, callerArn, callerAccount, true);
        }
        if (principalNode != null && !principalNode.isNull()) {
            return matchesResourcePrincipalBlock(principalNode, callerArn, callerAccount, false);
        }
        return false;
    }

    private static boolean matchesTrust(JsonNode principalNode, String callerArn, String callerAccount) {
        if (principalNode == null || principalNode.isNull()) {
            return false;
        }
        if (principalNode.isTextual()) {
            return matchesAwsTrustPrincipal(principalNode.asText(), callerArn, callerAccount);
        }
        if (principalNode.has("*")) {
            return true;
        }
        JsonNode aws = principalNode.get("AWS");
        if (aws != null) {
            if (aws.isTextual()) {
                return matchesAwsTrustPrincipal(aws.asText(), callerArn, callerAccount);
            }
            if (aws.isArray()) {
                for (JsonNode entry : aws) {
                    if (entry.isTextual()
                            && matchesAwsTrustPrincipal(entry.asText(), callerArn, callerAccount)) {
                        return true;
                    }
                }
            }
        }
        JsonNode federated = principalNode.get("Federated");
        if (federated != null && callerArn != null) {
            if (federated.isTextual()) {
                return matchesFederatedPrincipal(federated.asText(), callerArn);
            }
            if (federated.isArray()) {
                for (JsonNode entry : federated) {
                    if (entry.isTextual() && matchesFederatedPrincipal(entry.asText(), callerArn)) {
                        return true;
                    }
                }
            }
        }
        return matches(principalNode, callerArn, callerAccount);
    }

    private static boolean matchesResourcePrincipalBlock(JsonNode principalNode,
                                                         String callerArn,
                                                         String callerAccount,
                                                         boolean notPrincipalContext) {
        if (principalNode == null || principalNode.isNull()) {
            return notPrincipalContext;
        }
        if (principalNode.isTextual()) {
            return matchesAwsResourcePrincipal(
                    principalNode.asText(), callerArn, callerAccount, notPrincipalContext);
        }
        if (principalNode.has("*")) {
            return true;
        }
        JsonNode aws = principalNode.get("AWS");
        if (aws != null) {
            if (aws.isTextual()) {
                return matchesAwsResourcePrincipal(aws.asText(), callerArn, callerAccount, notPrincipalContext);
            }
            if (aws.isArray()) {
                for (JsonNode entry : aws) {
                    if (entry.isTextual()
                            && matchesAwsResourcePrincipal(
                            entry.asText(), callerArn, callerAccount, notPrincipalContext)) {
                        return true;
                    }
                }
            }
        }
        JsonNode service = principalNode.get("Service");
        if (service != null) {
            if (service.isTextual()) {
                return matchesServicePrincipal(service.asText(), callerArn);
            }
            if (service.isArray()) {
                for (JsonNode entry : service) {
                    if (entry.isTextual() && matchesServicePrincipal(entry.asText(), callerArn)) {
                        return true;
                    }
                }
            }
        }
        JsonNode federated = principalNode.get("Federated");
        if (federated != null && callerArn != null) {
            if (federated.isTextual()) {
                return matchesFederatedPrincipal(federated.asText(), callerArn);
            }
            if (federated.isArray()) {
                for (JsonNode entry : federated) {
                    if (entry.isTextual() && matchesFederatedPrincipal(entry.asText(), callerArn)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * @param principalNode {@code Principal} block; null means no restriction (legacy resource policies)
     */
    public static boolean matches(JsonNode principalNode, String callerArn, String callerAccount) {
        if (principalNode == null || principalNode.isNull()) {
            return true;
        }
        return matchesResourcePrincipalBlock(principalNode, callerArn, callerAccount, false);
    }

    public static boolean matchesAwsTrustPrincipal(String principal, String callerArn, String callerAccount) {
        if (principal == null || principal.isBlank()) {
            return false;
        }
        if ("*".equals(principal)) {
            return true;
        }
        if (principal.matches("\\d{12}")) {
            return principal.equals(resolveCallerAccount(callerArn, callerAccount));
        }
        if (principal.endsWith(":root")) {
            String principalAccount = AwsArnUtils.accountOrDefault(principal, "");
            String caller = resolveCallerAccount(callerArn, callerAccount);
            return !principalAccount.isBlank() && principalAccount.equals(caller);
        }
        return matchesAwsResourcePrincipal(principal, callerArn, callerAccount, false);
    }

    public static boolean matchesAwsPrincipal(String principal, String callerArn, String callerAccount) {
        return matchesAwsResourcePrincipal(principal, callerArn, callerAccount, false);
    }

    /**
     * Matches AWS principals in resource-based policies.
     *
     * @param notPrincipalContext when true, account identifiers match any identity in the account
     */
    static boolean matchesAwsResourcePrincipal(String principal,
                                                 String callerArn,
                                                 String callerAccount,
                                                 boolean notPrincipalContext) {
        if (principal == null || principal.isBlank()) {
            return false;
        }
        if ("*".equals(principal)) {
            return true;
        }
        if (isAccountIdentifier(principal)) {
            String principalAccount = accountFromPrincipal(principal);
            String caller = resolveCallerAccount(callerArn, callerAccount);
            if (notPrincipalContext) {
                return !principalAccount.isBlank() && principalAccount.equals(caller);
            }
            // Account root in a resource policy enables IAM delegation on AWS; it does not
            // directly authorize every IAM principal in the account.
            return callerArn != null
                    && (principal.equalsIgnoreCase(callerArn)
                    || IamPolicyEvaluator.globMatches(principal, callerArn)
                    || rootArnForAccount(principalAccount).equalsIgnoreCase(callerArn));
        }
        if (callerArn == null) {
            return false;
        }
        if (principal.equalsIgnoreCase(callerArn)) {
            return true;
        }
        if (IamPolicyEvaluator.globMatches(principal, callerArn)) {
            return true;
        }
        return matchesAssumedRoleSession(principal, callerArn);
    }

    private static boolean isAccountIdentifier(String principal) {
        return principal.matches("\\d{12}") || principal.endsWith(":root");
    }

    private static String accountFromPrincipal(String principal) {
        if (principal.matches("\\d{12}")) {
            return principal;
        }
        return AwsArnUtils.accountOrDefault(principal, "");
    }

    private static String rootArnForAccount(String accountId) {
        return "arn:aws:iam::" + accountId + ":root";
    }

    /**
     * IAM role principal ARNs also match active sessions for that role.
     */
    static boolean matchesAssumedRoleSession(String rolePrincipalArn, String callerArn) {
        if (rolePrincipalArn == null || callerArn == null
                || !rolePrincipalArn.contains(":role/")
                || !callerArn.contains(":assumed-role/")) {
            return false;
        }
        String roleAccount = AwsArnUtils.accountOrDefault(rolePrincipalArn, "");
        String callerAccount = AwsArnUtils.accountOrDefault(callerArn, "");
        if (roleAccount.isBlank() || !roleAccount.equals(callerAccount)) {
            return false;
        }
        int roleIdx = rolePrincipalArn.indexOf(":role/");
        int assumedIdx = callerArn.indexOf(":assumed-role/");
        String rolePathAndName = rolePrincipalArn.substring(roleIdx + ":role/".length());
        String assumedRemainder = callerArn.substring(assumedIdx + ":assumed-role/".length());
        int sessionSep = assumedRemainder.lastIndexOf('/');
        if (sessionSep < 0) {
            return false;
        }
        String assumedRolePathAndName = assumedRemainder.substring(0, sessionSep);
        if (rolePathAndName.equals(assumedRolePathAndName)) {
            return true;
        }
        String sessionArnPattern = "arn:aws:sts::" + roleAccount + ":assumed-role/" + rolePathAndName + "/*";
        return IamPolicyEvaluator.globMatches(sessionArnPattern, callerArn);
    }

    static boolean matchesFederatedPrincipal(String federated, String requestProvider) {
        if (federated == null || federated.isBlank() || requestProvider == null || requestProvider.isBlank()) {
            return false;
        }
        if (federated.equalsIgnoreCase(requestProvider)) {
            return true;
        }
        if (IamPolicyEvaluator.globMatches(federated, requestProvider)
                || IamPolicyEvaluator.globMatches(requestProvider, federated)) {
            return true;
        }
        String federatedHost = oidcProviderHost(federated);
        String requestHost = oidcProviderHost(requestProvider);
        if (!federatedHost.isBlank() && federatedHost.equalsIgnoreCase(requestHost)) {
            return true;
        }
        if (!federatedHost.isBlank() && requestProvider.equalsIgnoreCase(federatedHost)) {
            return true;
        }
        if (!requestHost.isBlank() && federated.equalsIgnoreCase(requestHost)) {
            return true;
        }
        return samlProviderName(federated).equalsIgnoreCase(samlProviderName(requestProvider))
                && !samlProviderName(federated).isBlank();
    }

    private static String oidcProviderHost(String providerPrincipal) {
        if (providerPrincipal == null) {
            return "";
        }
        int idx = providerPrincipal.indexOf(":oidc-provider/");
        if (idx >= 0) {
            return providerPrincipal.substring(idx + ":oidc-provider/".length());
        }
        return "";
    }

    private static String samlProviderName(String providerPrincipal) {
        if (providerPrincipal == null) {
            return "";
        }
        int idx = providerPrincipal.indexOf(":saml-provider/");
        if (idx >= 0) {
            return providerPrincipal.substring(idx + ":saml-provider/".length());
        }
        return "";
    }

    private static String resolveCallerAccount(String callerArn, String callerAccount) {
        if (callerAccount != null && !callerAccount.isBlank()) {
            return callerAccount;
        }
        return AwsArnUtils.accountOrDefault(callerArn, "");
    }

    private static boolean matchesServicePrincipal(String service, String callerArn) {
        if (service == null || service.isBlank() || callerArn == null) {
            return false;
        }
        // In-process delivery callers pass the bare service principal (e.g. "sns.amazonaws.com").
        if (service.equalsIgnoreCase(callerArn) || IamPolicyEvaluator.globMatches(service, callerArn)) {
            return true;
        }
        // Service-linked roles use path /aws-service-role/<service>/... Do not match solely
        // because RoleSessionName (or an IAM user/role name) equals the service string.
        return callerArn.contains("/aws-service-role/" + service + "/");
    }
}
