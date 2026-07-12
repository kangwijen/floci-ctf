package io.github.hectorvent.floci.fuzz.unit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.model.CallerContext;

import java.util.List;
import java.util.Map;

/**
 * Jazzer entry for {@link IamPolicyEvaluator}. Regression corpus when
 * {@code JAZZER_FUZZ=0}; mutates under profile {@code fuzz-jazzer}.
 */
class IamPolicyEvaluatorJazzerTest {

    private static final IamPolicyEvaluator EVALUATOR = new IamPolicyEvaluator(FuzzFixtures.objectMapper());
    private static final String[] ACTIONS = {
            "s3:GetObject", "s3:PutObject", "sqs:ReceiveMessage", "kms:Decrypt",
            "iam:GetUser", "sts:AssumeRole", "dynamodb:PutItem", "*"
    };

    @FuzzTest
    void fuzzEvaluate(FuzzedDataProvider data) {
        final String action = data.pickValue(ACTIONS);
        String resource = data.consumeString(512);
        if (resource.isBlank()) {
            resource = "arn:aws:s3:::bucket/key";
        }
        String policyDoc = data.consumeRemainingAsString();
        if (policyDoc.length() > 4096) {
            policyDoc = policyDoc.substring(0, 4096);
        }
        final String finalPolicyDoc = policyDoc;
        final String finalResource = resource;
        CallerContext caller = new CallerContext(List.of(finalPolicyDoc), null, null);
        String seed = action + "|" + finalResource + "|" + finalPolicyDoc;
        SecurityOracle.runCatching("IamPolicyEvaluator.jazzer", seed, () ->
                EVALUATOR.evaluate(caller, List.of(), action, finalResource, Map.of()));
    }
}
