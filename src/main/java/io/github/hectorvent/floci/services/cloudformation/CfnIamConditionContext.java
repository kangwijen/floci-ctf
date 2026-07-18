package io.github.hectorvent.floci.services.cloudformation;

import java.util.Map;

/**
 * Condition keys for in-process IAM checks that CloudFormation makes with the stack
 * creator credentials. Matches AWS {@code aws:CalledVia} when CloudFormation reuses
 * the caller identity to call other services (for example IAM).
 */
public final class CfnIamConditionContext {

    public static final String CLOUDFORMATION_SERVICE_PRINCIPAL = "cloudformation.amazonaws.com";

    private CfnIamConditionContext() {
    }

    /** Condition map fragment: {@code aws:CalledVia=cloudformation.amazonaws.com}. */
    public static Map<String, String> calledViaCloudFormation() {
        return Map.of("aws:calledvia", CLOUDFORMATION_SERVICE_PRINCIPAL);
    }
}
