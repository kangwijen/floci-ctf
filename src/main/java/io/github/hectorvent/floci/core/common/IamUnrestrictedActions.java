package io.github.hectorvent.floci.core.common;

import java.util.Map;
import java.util.Set;

/**
 * IAM actions that authenticated callers may invoke without an explicit Allow in
 * identity-based policies, matching AWS behavior where documented.
 *
 * <p>Applies to every emulated service reached through {@link IamEnforcementFilter}
 * on port 4566: once {@link io.github.hectorvent.floci.services.iam.IamActionRegistry}
 * resolves an action string, exemptions are checked here before
 * {@link io.github.hectorvent.floci.services.iam.IamPolicyEvaluator} runs.
 *
 * <p>SigV4, strict mode, and registered-access-key checks still apply; only policy
 * evaluation is skipped.
 *
 * <p>Per AWS API Reference and IAM User Guide searches, only STS documents
 * authentication operations that ignore identity-based Allow/Deny. Other services
 * (S3, EC2, IAM, DynamoDB, ...) require normal policy Allows.
 *
 * @see <a href="https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html">GetCallerIdentity</a>
 * @see <a href="https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html">GetSessionToken</a>
 */
public final class IamUnrestrictedActions {

    /**
     * Canonical IAM action strings with explicit AWS "no permissions required" (or
     * policy cannot control authentication) documentation.
     */
    private static final Set<String> EXEMPT_FROM_POLICY_EVALUATION = Set.of(
            "sts:GetCallerIdentity",
            "sts:GetSessionToken"
    );

    /**
     * Malformed Query {@code Action} values that should map to a documented exempt action.
     */
    private static final Map<String, String> ACTION_ALIASES = Map.of(
            "sts:Get+CallerIdentity", "sts:GetCallerIdentity"
    );

    private IamUnrestrictedActions() {
    }

    public static boolean isExemptFromPolicyEvaluation(String action) {
        if (action == null) {
            return false;
        }
        return EXEMPT_FROM_POLICY_EVALUATION.contains(canonicalAction(action));
    }

    /**
     * Normalizes a resolved IAM action (e.g. {@code sts:Get+CallerIdentity} from
     * form-urlencoded {@code Get%2BCallerIdentity}) for policy checks and routing.
     */
    public static String canonicalAction(String action) {
        if (action == null) {
            return null;
        }
        return ACTION_ALIASES.getOrDefault(action, action);
    }

    /**
     * Normalizes a Query-protocol operation name before it is combined with a scope.
     */
    public static String canonicalQueryOperation(String credentialScope, String operation) {
        if (operation == null || operation.isBlank()) {
            return operation;
        }
        return canonicalAction(credentialScope + ":" + operation)
                .substring(credentialScope.length() + 1);
    }

    /** For tests and documentation. */
    static Set<String> documentedExemptActions() {
        return Set.copyOf(EXEMPT_FROM_POLICY_EVALUATION);
    }
}
