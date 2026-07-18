package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * O21: Same-account KMS data-plane requires key policy Allow AND identity Allow
 * when a key policy document is present (AWS CMK semantics).
 */
@Tag("security-regression")
class KmsKeyPolicyAndIdentityTest {

    private static final String KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private static final String ACCOUNT = "111122223333";
    private static final String CALLER = "arn:aws:iam::111122223333:user/alice";

    private final IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());

    @Test
    void kmsEncryptDeniedWhenOnlyIdentityAllowsWithoutKeyPolicyAllow() {
        String identity = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"kms:Encrypt","Resource":"%s"}
                ]}""".formatted(KEY_ARN);
        String keyPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
                   "Action":"kms:DescribeKey","Resource":"*"}
                ]}""".formatted(ACCOUNT);

        Decision decision = evaluator.evaluate(
                CallerContext.of(List.of(identity)),
                List.of(keyPolicy),
                "kms:Encrypt",
                KEY_ARN,
                Map.of("aws:principalarn", CALLER, "aws:principalaccount", ACCOUNT));

        assertEquals(Decision.DENY, decision);
    }

    @Test
    void kmsEncryptAllowedWhenIdentityAndKeyPolicyBothAllow() {
        String identity = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"kms:Encrypt","Resource":"%s"}
                ]}""".formatted(KEY_ARN);
        String keyPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Sid":"Enable IAM User Permissions",
                   "Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},
                   "Action":"kms:*","Resource":"*"}
                ]}""".formatted(ACCOUNT);

        Decision decision = evaluator.evaluate(
                CallerContext.of(List.of(identity)),
                List.of(keyPolicy),
                "kms:Encrypt",
                KEY_ARN,
                Map.of("aws:principalarn", CALLER, "aws:principalaccount", ACCOUNT));

        assertEquals(Decision.ALLOW, decision);
    }

    @Test
    void nonKmsStillAllowsIdentityOrResource() {
        String identity = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
                ]}""";
        String bucketPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Principal":{"AWS":"*"},
                   "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}
                ]}""";

        Decision identityOnly = evaluator.evaluate(
                CallerContext.of(List.of(identity)),
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::b/k",
                Map.of("aws:principalarn", CALLER, "aws:principalaccount", ACCOUNT));
        Decision resourceOnly = evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::b/k",
                Map.of("aws:principalarn", CALLER, "aws:principalaccount", ACCOUNT));

        assertEquals(Decision.ALLOW, identityOnly);
        assertEquals(Decision.ALLOW, resourceOnly);
    }
}
