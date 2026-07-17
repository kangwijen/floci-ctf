package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IamPolicyEvaluatorTest {

    @Test
    void policyParseCacheReusesParsedDocuments() throws Exception {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}
            ]}""";

        assertEquals(Decision.ALLOW, evaluator.evaluate(List.of(policy), "s3:GetObject", "*"));
        assertEquals(Decision.ALLOW, evaluator.evaluate(List.of(policy), "s3:GetObject", "*"));

        Map<?, ?> cache = policyParseCache(evaluator);
        assertEquals(1, cache.size());
    }

    @Test
    void policyParseCacheEvictsOldestBeyondMaxSize() throws Exception {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        for (int i = 0; i < 501; i++) {
            String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-%d/*"}
                ]}""".formatted(i);
            evaluator.evaluate(List.of(policy), "s3:GetObject", "arn:aws:s3:::bucket-" + i + "/key");
        }

        Map<?, ?> cache = policyParseCache(evaluator);
        assertTrue(cache.size() <= 500, "cache size was " + cache.size());
    }

    @Test
    void globMatchesMultiWildcardAgainstLiteral() {
        assertTrue(IamPolicyEvaluator.globMatches("a*b*c", "axbyc"));
        assertTrue(IamPolicyEvaluator.globMatches("a*b*c", "abc"));
        assertFalse(IamPolicyEvaluator.globMatches("a*b*c", "abx"));
        assertTrue(IamPolicyEvaluator.globMatches("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key"));
    }

    @Test
    void globMatchesPathologicalMultiWildcardCompletesInLinearTime() {
        // Former recursive backtracking blew up on patterns like a*a*a*... vs a long run of 'a's.
        String pattern = "a*a*a*a*a*a*a*b";
        String value = "a".repeat(40);
        assertTimeoutPreemptively(Duration.ofMillis(200), () ->
                assertFalse(IamPolicyEvaluator.globMatches(pattern, value)));
        assertTimeoutPreemptively(Duration.ofMillis(200), () ->
                assertTrue(IamPolicyEvaluator.globMatches(pattern, value + "b")));
    }

    @Test
    void forAllValuesStringEqualsDeniesWhenEveryRequestValueMatches() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:TagUser","Resource":"*"},
              {"Effect":"Deny","Action":"iam:TagUser","Resource":"*",
               "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["environment","webserver"]}}}
            ]}""";

        Decision decision = evaluator.simulateCustomPolicy(List.of(policy), "iam:TagUser", "*",
                Map.of("aws:TagKeys", "environment,webserver"));

        assertEquals(Decision.DENY, decision);
    }

    @Test
    void forAllValuesStringEqualsAllowsWhenARequestValueDoesNotMatch() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:TagUser","Resource":"*"},
              {"Effect":"Deny","Action":"iam:TagUser","Resource":"*",
               "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["environment","webserver"]}}}
            ]}""";

        Decision decision = evaluator.simulateCustomPolicy(List.of(policy), "iam:TagUser", "*",
                Map.of("aws:TagKeys", "environment,unrelated-tag"));

        assertEquals(Decision.ALLOW, decision);
    }

    @Test
    void forAnyValueStringEqualsDeniesWhenAnyRequestValueMatches() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"ec2:CreateSnapshot","Resource":"*"},
              {"Effect":"Deny","Action":"ec2:CreateSnapshot","Resource":"*",
               "Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":"webserver"}}}
            ]}""";

        Decision decision = evaluator.simulateCustomPolicy(List.of(policy), "ec2:CreateSnapshot", "*",
                Map.of("aws:TagKeys", "environment,webserver"));

        assertEquals(Decision.DENY, decision);
    }

    @Test
    void forAnyValueStringEqualsAllowsWhenNoRequestValueMatches() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"ec2:CreateSnapshot","Resource":"*"},
              {"Effect":"Deny","Action":"ec2:CreateSnapshot","Resource":"*",
               "Condition":{"ForAnyValue:StringEquals":{"aws:TagKeys":"webserver"}}}
            ]}""";

        Decision decision = evaluator.simulateCustomPolicy(List.of(policy), "ec2:CreateSnapshot", "*",
                Map.of("aws:TagKeys", "environment,production"));

        assertEquals(Decision.ALLOW, decision);
    }

    @Test
    void forAllValuesOnMissingRequestKeyIsVacuouslyTrue() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:TagUser","Resource":"*"},
              {"Effect":"Deny","Action":"iam:TagUser","Resource":"*",
               "Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["environment"]}}}
            ]}""";

        Decision decision = evaluator.simulateCustomPolicy(List.of(policy), "iam:TagUser", "*", Map.of());

        assertEquals(Decision.DENY, decision);
    }

    @SuppressWarnings("unchecked")
    private static Map<?, ?> policyParseCache(IamPolicyEvaluator evaluator) throws Exception {
        Field field = IamPolicyEvaluator.class.getDeclaredField("policyParseCache");
        field.setAccessible(true);
        return (Map<?, ?>) field.get(evaluator);
    }
}
