package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

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
}
