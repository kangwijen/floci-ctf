package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Evaluates IAM role trust policies ({@code AssumeRolePolicyDocument}) for
 * {@code sts:AssumeRole} and related calls.
 */
@ApplicationScoped
public class AssumeRoleTrustPolicyEvaluator {

    private static final Logger LOG = Logger.getLogger(AssumeRoleTrustPolicyEvaluator.class);

    private final ObjectMapper objectMapper;
    private final IamPolicyEvaluator policyEvaluator;

    @Inject
    public AssumeRoleTrustPolicyEvaluator(ObjectMapper objectMapper, IamPolicyEvaluator policyEvaluator) {
        this.objectMapper = objectMapper;
        this.policyEvaluator = policyEvaluator;
    }

    /**
     * @param trustPolicyDocument role trust policy JSON
     * @param callerPrincipalArn  ARN of the calling principal (user, role, root, etc.)
     * @param externalId          {@code ExternalId} request parameter, or null if omitted
     * @return true if at least one Allow statement permits the assumption
     */
    public boolean isAssumeRoleTrusted(String trustPolicyDocument,
                                        String callerPrincipalArn,
                                        String externalId) {
        return isAssumeRoleTrusted(trustPolicyDocument, callerPrincipalArn, externalId, "sts:AssumeRole");
    }

    /**
     * @param stsAction STS API being invoked, e.g. {@code sts:AssumeRoleWithWebIdentity}
     */
    public boolean isAssumeRoleTrusted(String trustPolicyDocument,
                                        String callerPrincipalArn,
                                        String externalId,
                                        String stsAction) {
        return isAssumeRoleTrusted(trustPolicyDocument, callerPrincipalArn, externalId, stsAction, null);
    }

    public boolean isAssumeRoleTrusted(String trustPolicyDocument,
                                        String callerPrincipalArn,
                                        String externalId,
                                        String stsAction,
                                        FederatedTrustContext federatedContext) {
        if (trustPolicyDocument == null || trustPolicyDocument.isBlank()) {
            return false;
        }
        String requestedAction = stsAction == null || stsAction.isBlank() ? "sts:AssumeRole" : stsAction;
        String callerArn = callerPrincipalArn == null ? "" : callerPrincipalArn;
        String callerAccount = AwsArnUtils.accountOrDefault(callerArn, "");
        String federatedPrincipal = federatedContext == null ? null : federatedContext.federatedPrincipal();

        Map<String, String> conditionCtx = new LinkedHashMap<>();
        if (externalId != null && !externalId.isBlank()) {
            conditionCtx.put("sts:externalid", externalId);
        }
        conditionCtx.put("aws:principalarn", callerArn);
        if (!callerAccount.isBlank()) {
            conditionCtx.put("aws:principalaccount", callerAccount);
        }
        if (federatedContext != null) {
            federatedContext.conditionClaims().forEach((key, value) -> {
                if (key != null && value != null) {
                    conditionCtx.put(key.toLowerCase(), value);
                }
            });
        }

        try {
            JsonNode root = objectMapper.readTree(trustPolicyDocument);
            JsonNode statements = root.path("Statement");
            List<JsonNode> stmtList = new ArrayList<>();
            if (statements.isArray()) {
                statements.forEach(stmtList::add);
            } else if (statements.isObject()) {
                stmtList.add(statements);
            }
            for (JsonNode stmt : stmtList) {
                if ("Deny".equalsIgnoreCase(stmt.path("Effect").asText())
                        && matchesTrustStatement(stmt, callerArn, callerAccount, conditionCtx,
                        requestedAction, federatedPrincipal, "Deny")) {
                    return false;
                }
            }
            for (JsonNode stmt : stmtList) {
                if ("Allow".equalsIgnoreCase(stmt.path("Effect").asText())
                        && matchesTrustStatement(stmt, callerArn, callerAccount, conditionCtx,
                        requestedAction, federatedPrincipal, "Allow")) {
                    return true;
                }
            }
        } catch (Exception e) {
            LOG.warnv("Failed to parse trust policy: {0}", e.getMessage());
        }
        return false;
    }

    private boolean matchesTrustStatement(JsonNode stmt,
                                          String callerArn,
                                          String callerAccount,
                                          Map<String, String> conditionCtx,
                                          String requestedAction,
                                          String federatedPrincipal) {
        return matchesTrustStatement(stmt, callerArn, callerAccount, conditionCtx,
                requestedAction, federatedPrincipal, "Allow");
    }

    private boolean matchesTrustStatement(JsonNode stmt,
                                          String callerArn,
                                          String callerAccount,
                                          Map<String, String> conditionCtx,
                                          String requestedAction,
                                          String federatedPrincipal,
                                          String requiredEffect) {
        if (!requiredEffect.equalsIgnoreCase(stmt.path("Effect").asText())) {
            return false;
        }
        if (!matchesTrustAction(stmt.get("Action"), requestedAction)) {
            return false;
        }
        if (!PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                stmt.get("Principal"), stmt.get("NotPrincipal"), callerArn, callerAccount, federatedPrincipal)) {
            return false;
        }
        return matchesTrustConditions(stmt.get("Condition"), conditionCtx);
    }

    private boolean matchesTrustAction(JsonNode actionNode, String requestedAction) {
        if (actionNode == null) {
            return false;
        }
        List<String> actions = nodeToList(actionNode);
        for (String action : actions) {
            if (IamPolicyEvaluator.globMatches(action, requestedAction)
                    || IamPolicyEvaluator.globMatches(action, "sts:*")
                    || "*".equals(action)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesTrustConditions(JsonNode condNode, Map<String, String> conditionCtx) {
        if (condNode == null || condNode.isNull() || !condNode.isObject()) {
            return true;
        }
        Map<String, Map<String, List<String>>> conditions = parseConditions(condNode);
        if (conditions == null || conditions.isEmpty()) {
            return true;
        }
        return evaluateConditions(conditions, conditionCtx);
    }

    private boolean evaluateConditions(Map<String, Map<String, List<String>>> conditions,
                                         Map<String, String> ctx) {
        for (Map.Entry<String, Map<String, List<String>>> entry : conditions.entrySet()) {
            if (!evaluateConditionBlock(entry.getKey(), entry.getValue(), ctx)) {
                return false;
            }
        }
        return true;
    }

    private boolean evaluateConditionBlock(String operator,
                                           Map<String, List<String>> keyValueMap,
                                           Map<String, String> ctx) {
        boolean ifExists = operator.endsWith("IfExists");
        String baseOp = ifExists ? operator.substring(0, operator.length() - "IfExists".length()) : operator;

        for (Map.Entry<String, List<String>> entry : keyValueMap.entrySet()) {
            String condKey = entry.getKey().toLowerCase();
            List<String> condValues = entry.getValue();
            String ctxValue = ctx.get(condKey);

            if (ctxValue == null) {
                if (ifExists) {
                    continue;
                }
                return false;
            }

            boolean keyMatch = false;
            for (String condValue : condValues) {
                if (evaluateSingleCondition(baseOp, ctxValue, condValue, condKey)) {
                    keyMatch = true;
                    break;
                }
            }
            if (!keyMatch) {
                return false;
            }
        }
        return true;
    }

    private boolean evaluateSingleCondition(String operator, String ctxValue, String condValue, String condKey) {
        return switch (operator) {
            case "StringEquals" -> matchesStringEquals(ctxValue, condValue, condKey);
            case "StringNotEquals" -> !matchesStringEquals(ctxValue, condValue, condKey);
            case "StringEqualsIgnoreCase" -> matchesStringEqualsIgnoreCase(ctxValue, condValue, condKey);
            case "StringNotEqualsIgnoreCase" -> !matchesStringEqualsIgnoreCase(ctxValue, condValue, condKey);
            case "StringLike" -> matchesStringLike(ctxValue, condValue, condKey);
            case "StringNotLike" -> !matchesStringLike(ctxValue, condValue, condKey);
            case "ArnEquals", "ArnLike" -> IamPolicyEvaluator.globMatches(condValue, ctxValue);
            case "ArnNotEquals", "ArnNotLike" -> !IamPolicyEvaluator.globMatches(condValue, ctxValue);
            case "Bool" -> Boolean.parseBoolean(condValue) == Boolean.parseBoolean(ctxValue);
            case "Null" -> ("true".equalsIgnoreCase(condValue)) == (ctxValue == null || ctxValue.isBlank());
            case "IpAddress" -> matchesIpAddress(condValue, ctxValue);
            case "NotIpAddress" -> !matchesIpAddress(condValue, ctxValue);
            default -> {
                LOG.warnv("Unsupported trust condition operator: {0}", operator);
                yield false;
            }
        };
    }

    private static boolean matchesStringEquals(String ctxValue, String condValue, String condKey) {
        if (isMultiValuedConditionKey(condKey, ctxValue)) {
            return containsDelimitedValue(ctxValue, condValue, true);
        }
        return ctxValue.equals(condValue);
    }

    private static boolean matchesStringEqualsIgnoreCase(String ctxValue, String condValue, String condKey) {
        if (isMultiValuedConditionKey(condKey, ctxValue)) {
            return containsDelimitedValue(ctxValue, condValue, false);
        }
        return ctxValue.equalsIgnoreCase(condValue);
    }

    private static boolean matchesStringLike(String ctxValue, String condValue, String condKey) {
        if (isMultiValuedConditionKey(condKey, ctxValue)) {
            for (String value : splitDelimitedValues(ctxValue)) {
                if (IamPolicyEvaluator.globMatches(condValue, value)) {
                    return true;
                }
            }
            return false;
        }
        return IamPolicyEvaluator.globMatches(condValue, ctxValue);
    }

    private static boolean isMultiValuedConditionKey(String condKey, String ctxValue) {
        if (condKey == null) {
            return false;
        }
        if (condKey.endsWith(":amr") || "amr".equals(condKey)) {
            return true;
        }
        if ((condKey.endsWith(":aud") || "aud".equals(condKey)) && ctxValue != null && ctxValue.contains(",")) {
            return true;
        }
        return false;
    }

    private static boolean containsDelimitedValue(String ctxValue, String condValue, boolean caseSensitive) {
        for (String value : splitDelimitedValues(ctxValue)) {
            if (caseSensitive ? value.equals(condValue) : value.equalsIgnoreCase(condValue)) {
                return true;
            }
        }
        return false;
    }

    private static List<String> splitDelimitedValues(String ctxValue) {
        if (ctxValue == null || ctxValue.isBlank()) {
            return List.of();
        }
        List<String> values = new ArrayList<>();
        for (String part : ctxValue.split(",")) {
            if (!part.isBlank()) {
                values.add(part.trim());
            }
        }
        return values;
    }

    private Map<String, Map<String, List<String>>> parseConditions(JsonNode condNode) {
        Map<String, Map<String, List<String>>> result = new LinkedHashMap<>();
        condNode.fields().forEachRemaining(opEntry -> {
            Map<String, List<String>> kvMap = new LinkedHashMap<>();
            opEntry.getValue().fields().forEachRemaining(kvEntry ->
                    kvMap.put(kvEntry.getKey(), nodeToList(kvEntry.getValue())));
            result.put(opEntry.getKey(), kvMap);
        });
        return result.isEmpty() ? null : result;
    }

    private List<String> nodeToList(JsonNode node) {
        List<String> list = new ArrayList<>();
        if (node == null) {
            return list;
        }
        if (node.isTextual()) {
            list.add(node.asText());
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                list.add(item.asText());
            }
        }
        return list;
    }

    private static boolean matchesIpAddress(String condValue, String ctxValue) {
        if (ctxValue == null || ctxValue.isBlank()) {
            return false;
        }
        if (condValue.contains("/")) {
            return matchesCidr(condValue, ctxValue);
        }
        return condValue.equals(ctxValue);
    }

    private static boolean matchesCidr(String cidr, String ip) {
        try {
            String[] parts = cidr.split("/");
            int prefix = Integer.parseInt(parts[1]);
            long cidrAddr = ipToLong(parts[0]);
            long ipAddr = ipToLong(ip);
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            return (cidrAddr & mask) == (ipAddr & mask);
        } catch (Exception e) {
            return false;
        }
    }

    private static long ipToLong(String ip) {
        String[] octets = ip.split("\\.");
        long result = 0;
        for (String octet : octets) {
            result = (result << 8) | Integer.parseInt(octet);
        }
        return result;
    }
}
