package io.github.hectorvent.floci.services.iam;

import io.quarkus.test.junit.QuarkusTest;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import org.junit.jupiter.api.Test;

import jakarta.inject.Inject;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit-style tests for the IAM enforcement engine components:
 * {@link IamPolicyEvaluator}, {@link IamActionRegistry}, and glob matching.
 *
 * The full HTTP enforcement path (filter → evaluator) is covered by the SDK
 * compatibility test {@code IamEnforcementTest.java} in sdk-test-java.
 */
@QuarkusTest
class IamEnforcementIntegrationTest {

    @Inject
    IamPolicyEvaluator evaluator;

    @Inject
    IamService iamService;

    // =========================================================================
    // IamPolicyEvaluator — basic allow / deny / implicit-deny
    // =========================================================================

    @Test
    void allowMatchingAction() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}
            ]}""";
        assertEquals(Decision.ALLOW,
                evaluator.evaluate(List.of(policy), "s3:GetObject", "arn:aws:s3:::my-bucket/key"));
    }

    @Test
    void implicitDenyWhenNoPolicies() {
        assertEquals(Decision.DENY,
                evaluator.evaluate(List.of(), "s3:GetObject", "arn:aws:s3:::my-bucket/key"));
    }

    @Test
    void implicitDenyWhenNoMatchingStatement() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}
            ]}""";
        assertEquals(Decision.DENY,
                evaluator.evaluate(List.of(policy), "s3:GetObject", "arn:aws:s3:::my-bucket/key"));
    }

    @Test
    void explicitDenyOverridesAllow() {
        String allow = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:*","Resource":"*"}
            ]}""";
        String deny = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}
            ]}""";
        assertEquals(Decision.DENY,
                evaluator.evaluate(List.of(allow, deny), "s3:GetObject", "arn:aws:s3:::bucket/key"));
    }

    @Test
    void wildcardActionMatchesService() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:*","Resource":"*"}
            ]}""";
        assertEquals(Decision.ALLOW,
                evaluator.evaluate(List.of(policy), "s3:DeleteObject", "arn:aws:s3:::bucket/key"));
    }

    @Test
    void fullyWildcardPolicyAllowsAnything() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"*","Resource":"*"}
            ]}""";
        assertEquals(Decision.ALLOW,
                evaluator.evaluate(List.of(policy), "lambda:InvokeFunction",
                        "arn:aws:lambda:us-east-1:000000000000:function:my-fn"));
    }

    @Test
    void resourceArnPatternMatchesBucket() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::my-bucket/*"}
            ]}""";
        assertEquals(Decision.ALLOW,
                evaluator.evaluate(List.of(policy), "s3:GetObject", "arn:aws:s3:::my-bucket/sub/key.txt"));
        assertEquals(Decision.DENY,
                evaluator.evaluate(List.of(policy), "s3:GetObject", "arn:aws:s3:::other-bucket/key"));
    }

    @Test
    void actionListInStatement() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(List.of(policy), "s3:GetObject", "*"));
        assertEquals(Decision.ALLOW, evaluator.evaluate(List.of(policy), "s3:PutObject", "*"));
        assertEquals(Decision.DENY, evaluator.evaluate(List.of(policy), "s3:DeleteObject", "*"));
    }

    @Test
    void malformedPolicyDocumentIsSkipped() {
        // Should not throw; malformed doc is silently ignored
        assertEquals(Decision.DENY,
                evaluator.evaluate(List.of("not-json"), "s3:GetObject", "*"));
    }

    @Test
    void conditionContextKeysAreCaseInsensitive() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
               "Condition":{"StringEquals":{"aws:SourceIp":"127.0.0.1"}}}
            ]}""";

        assertEquals(Decision.ALLOW,
                evaluator.simulateCustomPolicy(
                        List.of(policy),
                        "s3:GetObject",
                        "arn:aws:s3:::bucket/key",
                        Map.of("AWS:SourceIP", "127.0.0.1")));
    }

    // =========================================================================
    // IamPolicyEvaluator.globMatches — unit tests
    // =========================================================================

    @Test
    void globMatchesStar() {
        assertTrue(IamPolicyEvaluator.globMatches("s3:*", "s3:GetObject"));
        assertTrue(IamPolicyEvaluator.globMatches("*", "anything"));
        assertFalse(IamPolicyEvaluator.globMatches("s3:*", "lambda:InvokeFunction"));
    }

    @Test
    void globMatchesLiteral() {
        assertTrue(IamPolicyEvaluator.globMatches("s3:GetObject", "s3:GetObject"));
        assertFalse(IamPolicyEvaluator.globMatches("s3:GetObject", "s3:PutObject"));
    }

    @Test
    void globMatchesQuestionMark() {
        assertTrue(IamPolicyEvaluator.globMatches("s3:GetObjec?", "s3:GetObject"));
        assertFalse(IamPolicyEvaluator.globMatches("s3:GetObjec?", "s3:GetObjects"));
    }

    @Test
    void globMatchesCaseInsensitive() {
        assertTrue(IamPolicyEvaluator.globMatches("S3:GetObject", "s3:getobject"));
    }

    @Test
    void globMatchesArnWildcard() {
        assertTrue(IamPolicyEvaluator.globMatches(
                "arn:aws:s3:::my-bucket/*",
                "arn:aws:s3:::my-bucket/sub/dir/file.txt"));
        assertFalse(IamPolicyEvaluator.globMatches(
                "arn:aws:s3:::my-bucket/*",
                "arn:aws:s3:::other-bucket/file.txt"));
    }

    @Test
    void globMatchesPathologicalPatternDoesNotHang() {
        String pattern = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa*a*a*a*a*a*a*b";
        String value = "a".repeat(40);
        assertFalse(IamPolicyEvaluator.globMatches(pattern, value));
    }

    // =========================================================================
    // Scoped ARN matching — SSM and STS with non-default account
    // =========================================================================

    @Test
    void allowSsmGetParameterWithExactAccountScopedArn() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"ssm:GetParameter",
               "Resource":"arn:aws:ssm:us-east-1:987654321098:parameter/polaris/starbase/counter"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "ssm:GetParameter",
                "arn:aws:ssm:us-east-1:987654321098:parameter/polaris/starbase/counter"));
    }

    @Test
    void denySsmGetParameterWithDifferentParameterInExactPolicy() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"ssm:GetParameter",
               "Resource":"arn:aws:ssm:us-east-1:987654321098:parameter/polaris/starbase/counter"}
            ]}""";
        assertEquals(Decision.DENY, evaluator.evaluate(
                List.of(policy), "ssm:GetParameter",
                "arn:aws:ssm:us-east-1:987654321098:parameter/capella/landing"));
    }

    @Test
    void allowSsmGetParameterWithPrefixWildcard() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"ssm:GetParameter",
               "Resource":"arn:aws:ssm:*:*:parameter/polaris/starbase/*"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "ssm:GetParameter",
                "arn:aws:ssm:us-east-1:987654321098:parameter/polaris/starbase/counter"));
        assertEquals(Decision.DENY, evaluator.evaluate(
                List.of(policy), "ssm:GetParameter",
                "arn:aws:ssm:us-east-1:987654321098:parameter/orion/comm"));
    }

    @Test
    void allowStsAssumeRoleWithExactRoleArn() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sts:AssumeRole",
               "Resource":"arn:aws:iam::987654321098:role/polaris-admin-access"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "sts:AssumeRole",
                "arn:aws:iam::987654321098:role/polaris-admin-access"));
    }

    @Test
    void denyStsAssumeRoleWithDifferentRoleInExactPolicy() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sts:AssumeRole",
               "Resource":"arn:aws:iam::987654321098:role/polaris-admin-access"}
            ]}""";
        assertEquals(Decision.DENY, evaluator.evaluate(
                List.of(policy), "sts:AssumeRole",
                "arn:aws:iam::987654321098:role/capella-readonly"));
    }

    @Test
    void allowStsAssumeRoleWithRoleWildcard() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sts:AssumeRole",
               "Resource":"arn:aws:iam::987654321098:role/*"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "sts:AssumeRole",
                "arn:aws:iam::987654321098:role/polaris-admin-access"));
    }

    @Test
    void listBucketPrefixConditionAllowsEscrowOnly() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::data",
               "Condition":{"StringLike":{"s3:prefix":["allowed/*"]}}}
            ]}""";
        Map<String, String> escrowCtx = Map.of("s3:prefix", "allowed/");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of(policy)),
                List.of(),
                "s3:ListBucket",
                "arn:aws:s3:::data",
                escrowCtx));
        Map<String, String> archivedCtx = Map.of("s3:prefix", "archived/");
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of(policy)),
                List.of(),
                "s3:ListBucket",
                "arn:aws:s3:::data",
                archivedCtx));
    }

    @Test
    void numericEqualsFailsClosedOnNonNumericContext() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"*",
               "Condition":{"NumericEquals":{"aws:EpochTime":["1700000000"]}}}
            ]}""";
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of(policy)),
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::bucket/key",
                Map.of("aws:EpochTime", "not-a-number")));
    }

    @Test
    void listBucketPrefixConditionFailsWhenPrefixMissingFromContext() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::data",
               "Condition":{"StringLike":{"s3:prefix":["allowed/*"]}}}
            ]}""";
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of(policy)),
                List.of(),
                "s3:ListBucket",
                "arn:aws:s3:::data",
                Map.of()));
    }

    @Test
    void sessionPolicyFromGetSessionTokenConstrainsTempCredentials() {
        String parentPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}
            ]}""";
        String sessionPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/allowed/*"}
            ]}""";
        iamService.createUser("session-parent", "/");
        String parentAccessKeyId = iamService.createAccessKey("session-parent").getAccessKeyId();
        iamService.putUserPolicy("session-parent", "get-vault", parentPolicy);
        String sessionArn = "arn:aws:sts::000000000000:federated-user/floci-session";
        iamService.registerSession(
                "ASIATESTSESSION01",
                sessionArn,
                Instant.now().plusSeconds(3600),
                sessionPolicy,
                "secret",
                "000000000000:floci-session",
                sessionArn,
                parentAccessKeyId,
                null);
        CallerContext caller = iamService.resolveCallerContext("ASIATESTSESSION01");
        Map<String, String> ctx = Map.of(
                "aws:principalarn", sessionArn,
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                caller, List.of(), "s3:GetObject", "arn:aws:s3:::data/allowed/object.txt", ctx));
        assertEquals(Decision.DENY, evaluator.evaluate(
                caller, List.of(), "s3:GetObject", "arn:aws:s3:::data/other/object.txt", ctx));
    }

    @Test
    void sessionPolicyWithoutParentGrantDoesNotExpandPermissions() {
        String sessionPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}
            ]}""";
        String sessionArn = "arn:aws:sts::000000000000:federated-user/floci-session";
        iamService.registerSession(
                "ASIATESTSESSION03",
                sessionArn,
                Instant.now().plusSeconds(3600),
                sessionPolicy,
                "secret",
                "000000000000:floci-session",
                sessionArn);
        CallerContext caller = iamService.resolveCallerContext("ASIATESTSESSION03");
        Map<String, String> ctx = Map.of(
                "aws:principalarn", sessionArn,
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.DENY, evaluator.evaluate(
                caller, List.of(), "s3:GetObject", "arn:aws:s3:::data/object.txt", ctx));
    }

    @Test
    void getSessionTokenSessionPolicyCannotExceedParentUserPolicy() {
        String parentPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::data"}
            ]}""";
        String sessionPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}
            ]}""";
        iamService.createUser("parent-user", "/");
        String parentAccessKeyId = iamService.createAccessKey("parent-user").getAccessKeyId();
        iamService.putUserPolicy("parent-user", "list-only", parentPolicy);
        String sessionArn = "arn:aws:sts::000000000000:federated-user/floci-session";
        iamService.registerSession(
                "ASIATESTSESSION02",
                sessionArn,
                Instant.now().plusSeconds(3600),
                sessionPolicy,
                "secret",
                "000000000000:floci-session",
                sessionArn,
                parentAccessKeyId);

        CallerContext caller = iamService.resolveCallerContext("ASIATESTSESSION02");
        Map<String, String> ctx = Map.of(
                "aws:principalarn", sessionArn,
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.DENY, evaluator.evaluate(
                caller, List.of(), "s3:GetObject", "arn:aws:s3:::data/object.txt", ctx));
    }

    @Test
    void allowIamCreatePolicyVersionOnPolicyArn() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:CreatePolicyVersion",
               "Resource":"arn:aws:iam::226767940554:policy/PathfindingPolicy"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "iam:CreatePolicyVersion",
                "arn:aws:iam::226767940554:policy/PathfindingPolicy"));
        assertEquals(Decision.DENY, evaluator.evaluate(
                List.of(policy), "iam:CreatePolicyVersion",
                "arn:aws:iam::226767940554:policy/OtherPolicy"));
    }

    @Test
    void allowIamCreateAccessKeyOnPolarisUserArn() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iam:CreateAccessKey",
               "Resource":"arn:aws:iam::226767940554:user/polaris"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "iam:CreateAccessKey",
                "arn:aws:iam::226767940554:user/polaris"));
        assertEquals(Decision.DENY, evaluator.evaluate(
                List.of(policy), "iam:CreateAccessKey",
                "arn:aws:iam::226767940554:user/random"));
    }

    // =========================================================================
    // Resource-based policies (Phase 2)
    // =========================================================================

    @Test
    void bucketPolicyAllowsWithoutIdentityPolicy() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},
               "Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::scoped-bucket/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/reader",
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::scoped-bucket/object-allowed.txt",
                ctx));
    }

    @Test
    void bucketPolicyDeniesWrongPrincipal() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},
               "Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::scoped-bucket/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/other",
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::scoped-bucket/object-allowed.txt",
                ctx));
    }

    @Test
    void identityOrResourcePolicyEitherCanAllow() {
        String identity = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::my-bucket"}
            ]}""";
        String bucket = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},
               "Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/x",
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of(identity)),
                List.of(bucket),
                "s3:ListBucket",
                "arn:aws:s3:::my-bucket",
                ctx));
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucket),
                "s3:GetObject",
                "arn:aws:s3:::other-bucket/key",
                ctx));
    }

    @Test
    void accountRootPrincipalDoesNotMatchIamUserInSameAccount() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"arn:aws:iam::111122223333:root"},
               "Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::shared/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::111122223333:user/reader",
                "aws:principalaccount", "111122223333");
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::shared/key",
                ctx));
    }

    @Test
    void accountIdPrincipalDoesNotMatchIamUserInSameAccount() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"111122223333"},
               "Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::shared/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::111122223333:user/reader",
                "aws:principalaccount", "111122223333");
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::shared/key",
                ctx));
    }

    @Test
    void resourcePolicyRolePrincipalMatchesAssumedRoleSession() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"arn:aws:iam::111122223333:role/DeployRole"},
               "Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::shared/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn",
                "arn:aws:sts::111122223333:assumed-role/DeployRole/session-1",
                "aws:principalaccount", "111122223333");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::shared/key",
                ctx));
    }

    @Test
    void notPrincipalDeniesListedPrincipal() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "NotPrincipal":{"AWS":"arn:aws:iam::000000000000:user/blocked"},
               "Action":"s3:GetObject",
               "Resource":"arn:aws:s3:::b/*"}
            ]}""";
        Map<String, String> allowed = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/allowed",
                "aws:principalaccount", "000000000000");
        Map<String, String> blocked = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/blocked",
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of()), List.of(bucketPolicy),
                "s3:GetObject", "arn:aws:s3:::b/k", allowed));
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of()), List.of(bucketPolicy),
                "s3:GetObject", "arn:aws:s3:::b/k", blocked));
    }

    @Test
    void secretsResourcePolicyAllowsWithoutIdentityPolicy() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow",
               "Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},
               "Action":"secretsmanager:GetSecretValue",
               "Resource":"*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/reader",
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(policy),
                "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:us-east-1:000000000000:secret:my-secret-000000",
                ctx));
    }

    @Test
    void resourcePolicyExplicitDenyOverridesResourceAllow() {
        String bucketPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},
               "Action":"s3:*","Resource":"arn:aws:s3:::b/*"},
              {"Effect":"Deny","Principal":{"AWS":"*"},
               "Action":"s3:GetObject","Resource":"arn:aws:s3:::b/secret/*"}
            ]}""";
        Map<String, String> ctx = Map.of(
                "aws:principalarn", "arn:aws:iam::000000000000:user/x",
                "aws:principalaccount", "000000000000");
        assertEquals(Decision.DENY, evaluator.evaluate(
                CallerContext.of(List.of()),
                List.of(bucketPolicy),
                "s3:GetObject",
                "arn:aws:s3:::b/secret/flag",
                ctx));
    }

    @Test
    void allowDynamodbGetItemOnPolarisTableArn() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"dynamodb:GetItem",
               "Resource":"arn:aws:dynamodb:us-east-1:226767940554:table/polaris"}
            ]}""";
        assertEquals(Decision.ALLOW, evaluator.evaluate(
                List.of(policy), "dynamodb:GetItem",
                "arn:aws:dynamodb:us-east-1:226767940554:table/polaris"));
        assertEquals(Decision.DENY, evaluator.evaluate(
                List.of(policy), "dynamodb:GetItem",
                "arn:aws:dynamodb:us-east-1:226767940554:table/random"));
    }
}
