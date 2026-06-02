package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IamUnrestrictedActionsTest {

    @Test
    void documentedStsActionsAreExempt() {
        for (String action : IamUnrestrictedActions.documentedExemptActions()) {
            assertTrue(IamUnrestrictedActions.isExemptFromPolicyEvaluation(action), action);
        }
    }

    @Test
    void getCallerIdentityAliasFromFormEncodingIsExempt() {
        assertTrue(IamUnrestrictedActions.isExemptFromPolicyEvaluation("sts:Get+CallerIdentity"));
        assertEquals("sts:GetCallerIdentity",
                IamUnrestrictedActions.canonicalAction("sts:Get+CallerIdentity"));
    }

    @Test
    void canonicalQueryOperationFixesStsCallerIdentity() {
        assertEquals("GetCallerIdentity",
                IamUnrestrictedActions.canonicalQueryOperation("sts", "Get+CallerIdentity"));
    }

    @Test
    void otherActionsRequirePolicyEvaluation() {
        assertFalse(IamUnrestrictedActions.isExemptFromPolicyEvaluation("sts:AssumeRole"));
        assertFalse(IamUnrestrictedActions.isExemptFromPolicyEvaluation("sts:GetAccessKeyInfo"));
        assertFalse(IamUnrestrictedActions.isExemptFromPolicyEvaluation("s3:ListAllMyBuckets"));
        assertFalse(IamUnrestrictedActions.isExemptFromPolicyEvaluation("ec2:DescribeRegions"));
        assertFalse(IamUnrestrictedActions.isExemptFromPolicyEvaluation("iam:GetUser"));
        assertFalse(IamUnrestrictedActions.isExemptFromPolicyEvaluation(null));
    }
}
