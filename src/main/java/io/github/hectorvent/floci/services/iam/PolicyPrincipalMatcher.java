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
     * Evaluates the principal dimension of a resource or trust statement.
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
            return !matches(principalNodeFromNot(notPrincipalNode), callerArn, callerAccount);
        }
        if (principalNode != null && !principalNode.isNull()) {
            return matches(principalNode, callerArn, callerAccount);
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
        if (principalNode.isTextual()) {
            return matchesAwsPrincipal(principalNode.asText(), callerArn, callerAccount);
        }
        if (principalNode.has("*")) {
            return true;
        }
        JsonNode aws = principalNode.get("AWS");
        if (aws != null) {
            if (aws.isTextual()) {
                return matchesAwsPrincipal(aws.asText(), callerArn, callerAccount);
            }
            if (aws.isArray()) {
                for (JsonNode entry : aws) {
                    if (entry.isTextual() && matchesAwsPrincipal(entry.asText(), callerArn, callerAccount)) {
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
                return IamPolicyEvaluator.globMatches(federated.asText(), callerArn)
                        || federated.asText().equalsIgnoreCase(callerArn);
            }
            if (federated.isArray()) {
                for (JsonNode entry : federated) {
                    if (entry.isTextual()
                            && (IamPolicyEvaluator.globMatches(entry.asText(), callerArn)
                            || entry.asText().equalsIgnoreCase(callerArn))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static JsonNode principalNodeFromNot(JsonNode notPrincipalNode) {
        return notPrincipalNode;
    }

    public static boolean matchesAwsPrincipal(String principal, String callerArn, String callerAccount) {
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
            return !principalAccount.isBlank()
                    && principalAccount.equals(resolveCallerAccount(callerArn, callerAccount));
        }
        return callerArn != null
                && (IamPolicyEvaluator.globMatches(principal, callerArn)
                || principal.equalsIgnoreCase(callerArn));
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
        if (callerArn.contains(":assumed-role/")) {
            return IamPolicyEvaluator.globMatches(service, callerArn);
        }
        return IamPolicyEvaluator.globMatches(service, callerArn);
    }
}
