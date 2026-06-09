package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

    @SuppressWarnings("unchecked")
    private static Map<?, ?> policyParseCache(IamPolicyEvaluator evaluator) throws Exception {
        Field field = IamPolicyEvaluator.class.getDeclaredField("policyParseCache");
        field.setAccessible(true);
        return (Map<?, ?>) field.get(evaluator);
    }
}
