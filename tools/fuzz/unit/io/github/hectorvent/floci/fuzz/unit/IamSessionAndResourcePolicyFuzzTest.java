package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.PolicyPrincipalMatcher;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

import java.util.List;
import java.util.Map;

/**
 * Session-policy intersection and resource-policy merge security oracles.
 */
class IamSessionAndResourcePolicyFuzzTest {

    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final IamPolicyEvaluator EVALUATOR = new IamPolicyEvaluator(MAPPER);
    private static final String ACCOUNT = "111122223333";
    private static final String ROOT_ARN = "arn:aws:iam::" + ACCOUNT + ":root";
    private static final String REGION = "us-east-1";

    private static final String IDENTITY_ALLOW_STAR = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"*","Resource":"*"}
            ]}""";

    private static final String SESSION_ALLOW_S3 = CorpusLoader.filesUnder("policy").stream()
            .filter(doc -> doc.contains("fuzz-bucket"))
            .findFirst()
            .orElse("""
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],
                       "Resource":["arn:aws:s3:::fuzz-bucket","arn:aws:s3:::fuzz-bucket/*"]}
                    ]}""");

    private static final String RESOURCE_ROOT_POLICY = CorpusLoader.filesUnder("policy").stream()
            .filter(doc -> doc.contains(":root"))
            .findFirst()
            .orElse("""
                    {"Version":"2012-10-17","Statement":[
                      {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},
                       "Action":"sqs:ReceiveMessage","Resource":"*"}
                    ]}""");

    @Property(tries = 50)
    void sessionPolicyNeverWidensBeyondIdentityOrResource(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String bucketSuffix) {
        String bucket = "data-" + bucketSuffix;
        String identityPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::%s"}
                ]}""".formatted(bucket);
        String sessionPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}
                ]}""".formatted(bucket);
        CallerContext caller = new CallerContext(List.of(identityPolicy), sessionPolicy, null);
        Map<String, String> ctx = principalCtx("arn:aws:iam::" + ACCOUNT + ":user/session-parent");

        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                caller,
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::" + bucket + "/object.txt",
                ctx);
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.sessionIntersection",
                bucket,
                "session Allow must not widen identity ListBucket to GetObject");
    }

    @Property(tries = 50)
    void sessionPolicyAloneDoesNotGrantWithoutBaseAllow(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String objectKey) {
        CallerContext caller = new CallerContext(List.of(), SESSION_ALLOW_S3, null);
        Map<String, String> ctx = principalCtx("arn:aws:iam::" + ACCOUNT + ":user/no-identity");

        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                caller,
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::fuzz-bucket/" + objectKey,
                ctx);
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.sessionOnly",
                objectKey,
                "session policy without identity/resource base grant must deny");
    }

    @Property(tries = 50)
    void sessionIntersectionNarrowsIdentityAllow(
            @ForAll @AlphaChars @StringLength(min = 1, max = 12) String deniedKey) {
        String identityPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::vault/*"}
                ]}""";
        String sessionPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::vault/allowed/*"}
                ]}""";
        CallerContext caller = new CallerContext(List.of(identityPolicy), sessionPolicy, null);
        Map<String, String> ctx = principalCtx("arn:aws:sts::" + ACCOUNT + ":assumed-role/reader/s1");

        IamPolicyEvaluator.Decision allowed = EVALUATOR.evaluate(
                caller, List.of(), "s3:GetObject", "arn:aws:s3:::vault/allowed/obj", ctx);
        IamPolicyEvaluator.Decision denied = EVALUATOR.evaluate(
                caller, List.of(), "s3:GetObject", "arn:aws:s3:::vault/" + deniedKey + "/obj", ctx);

        SecurityOracle.expectAllow(
                allowed == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.sessionNarrow",
                "allowed",
                "intersection should allow when both identity and session match");
        SecurityOracle.expectDeny(
                denied == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.sessionNarrow",
                deniedKey,
                "session policy must narrow identity Allow beyond session scope");
    }

    @Property(tries = 40)
    void explicitDenyInIdentityBeatsSessionAllow(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String key) {
        String denyPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::secret/*"}
                ]}""";
        CallerContext caller = new CallerContext(
                List.of(IDENTITY_ALLOW_STAR, denyPolicy),
                SESSION_ALLOW_S3,
                null);
        Map<String, String> ctx = principalCtx("arn:aws:iam::" + ACCOUNT + ":user/reader");

        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                caller,
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::secret/" + key,
                ctx);
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.identityDeny",
                key,
                "identity explicit Deny must beat session Allow");
    }

    @Property(tries = 40)
    void explicitDenyInSessionBeatsIdentityAllow(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String key) {
        String sessionDeny = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::vault-deny/*"}
                ]}""";
        CallerContext caller = new CallerContext(
                List.of(IDENTITY_ALLOW_STAR),
                sessionDeny,
                null);
        Map<String, String> ctx = principalCtx("arn:aws:iam::" + ACCOUNT + ":user/reader");

        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                caller,
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::vault-deny/" + key,
                ctx);
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.sessionDeny",
                key,
                "session explicit Deny must beat identity Allow");
    }

    @Property(tries = 40)
    void explicitDenyInResourceBeatsIdentityAndSessionAllow(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String key) {
        String resourceDeny = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Deny","Principal":{"AWS":"*"},
                   "Action":"s3:GetObject","Resource":"arn:aws:s3:::blocked/%s"}
                ]}""".formatted(key);
        CallerContext caller = new CallerContext(List.of(IDENTITY_ALLOW_STAR), SESSION_ALLOW_S3, null);
        Map<String, String> ctx = principalCtx("arn:aws:iam::" + ACCOUNT + ":user/reader");

        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                caller,
                List.of(resourceDeny),
                "s3:GetObject",
                "arn:aws:s3:::blocked/" + key,
                ctx);
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.resourceDeny",
                key,
                "resource explicit Deny must beat identity and session Allow");
    }

    @Property(tries = 50)
    void resourcePolicyAccountRootDoesNotAuthorizeIamUser(
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String userName) throws Exception {
        String userArn = "arn:aws:iam::" + ACCOUNT + ":user/" + userName;
        JsonNode principal = MAPPER.readTree("{\"AWS\":\"" + ROOT_ARN + "\"}");
        boolean matcherSaysMatch = PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, userArn, ACCOUNT);
        SecurityOracle.expectNoAuthBypass(
                matcherSaysMatch,
                "PolicyPrincipalMatcher.resourceRoot",
                userArn,
                "account :root must not match IAM user on resource policies");

        Map<String, String> ctx = principalCtx(userArn);
        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                CallerContext.of(List.of()),
                List.of(RESOURCE_ROOT_POLICY),
                "sqs:ReceiveMessage",
                "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":fuzz-queue",
                ctx);
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.resourceRoot",
                userArn,
                "resource :root Allow must not authorize IAM user");
    }

    @Property(tries = 40)
    void resourceOnlyAllowAuthorizesMatchingPrincipal(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String queueName,
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String userName) {
        String userArn = "arn:aws:iam::" + ACCOUNT + ":user/" + userName;
        String queueArn = "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":" + queueName;
        String resourcePolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Principal":{"AWS":"%s"},
                   "Action":"sqs:ReceiveMessage","Resource":"%s"}
                ]}""".formatted(userArn, queueArn);

        Map<String, String> matchingCtx = principalCtx(userArn);
        IamPolicyEvaluator.Decision allow = EVALUATOR.evaluate(
                CallerContext.of(List.of()),
                List.of(resourcePolicy),
                "sqs:ReceiveMessage",
                queueArn,
                matchingCtx);
        SecurityOracle.expectAllow(
                allow == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.resourceOnlyAllow",
                userArn,
                "resource-only Allow should authorize matching IAM principal");

        String otherArn = "arn:aws:iam::" + ACCOUNT + ":user/other-" + userName;
        IamPolicyEvaluator.Decision deny = EVALUATOR.evaluate(
                CallerContext.of(List.of()),
                List.of(resourcePolicy),
                "sqs:ReceiveMessage",
                queueArn,
                principalCtx(otherArn));
        SecurityOracle.expectDeny(
                deny == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.resourceOnlyAllow",
                otherArn,
                "resource-only Allow must not authorize non-matching principal");
    }

    @Property(tries = 40)
    void identityOrResourceMergeAllowsWhenEitherGrants(
            @ForAll @AlphaChars @StringLength(min = 1, max = 16) String userName) {
        String userArn = "arn:aws:iam::" + ACCOUNT + ":user/" + userName;
        String identityPolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::identity-only/*"}
                ]}""";
        String resourcePolicy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Principal":{"AWS":"%s"},
                   "Action":"s3:GetObject","Resource":"arn:aws:s3:::resource-only/*"}
                ]}""".formatted(userArn);
        Map<String, String> ctx = principalCtx(userArn);

        IamPolicyEvaluator.Decision viaIdentity = EVALUATOR.evaluate(
                new CallerContext(List.of(identityPolicy), null, null),
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::identity-only/key",
                ctx);
        IamPolicyEvaluator.Decision viaResource = EVALUATOR.evaluate(
                CallerContext.of(List.of()),
                List.of(resourcePolicy),
                "s3:GetObject",
                "arn:aws:s3:::resource-only/key",
                ctx);

        SecurityOracle.expectAllow(
                viaIdentity == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.identityOrResource",
                userName,
                "identity Allow should grant without resource policy");
        SecurityOracle.expectAllow(
                viaResource == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.identityOrResource",
                userArn,
                "resource Allow should grant without identity policy when principal matches");
    }

    @Property(tries = 60)
    void malformedSessionPolicyNeverThrowsError(@ForAll @StringLength(max = 300) String sessionDoc) {
        CallerContext caller = new CallerContext(List.of(IDENTITY_ALLOW_STAR), sessionDoc, null);
        SecurityOracle.runCatching("IamPolicyEvaluator.malformedSession", sessionDoc, () ->
                EVALUATOR.evaluate(
                        caller,
                        List.of(),
                        "s3:GetObject",
                        "arn:aws:s3:::b/k",
                        principalCtx("arn:aws:iam::" + ACCOUNT + ":user/x")));
    }

    @Property(tries = 60)
    void malformedResourcePolicyNeverThrowsError(@ForAll @StringLength(max = 300) String resourceDoc) {
        SecurityOracle.runCatching("IamPolicyEvaluator.malformedResource", resourceDoc, () ->
                EVALUATOR.evaluate(
                        CallerContext.of(List.of(IDENTITY_ALLOW_STAR)),
                        List.of(resourceDoc),
                        "sqs:ReceiveMessage",
                        "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":q",
                        principalCtx("arn:aws:iam::" + ACCOUNT + ":user/x")));
    }

    @Property(tries = 40)
    void malformedIdentityWithSessionNeverThrowsError(
            @ForAll @StringLength(max = 200) String identityDoc,
            @ForAll @StringLength(max = 200) String sessionDoc) {
        CallerContext caller = new CallerContext(List.of(identityDoc), sessionDoc, null);
        String seed = identityDoc + "|" + sessionDoc;
        SecurityOracle.runCatching("IamPolicyEvaluator.malformedBoth", seed, () ->
                EVALUATOR.evaluate(
                        caller,
                        List.of(RESOURCE_ROOT_POLICY),
                        "s3:GetObject",
                        "arn:aws:s3:::b/k",
                        principalCtx("arn:aws:iam::" + ACCOUNT + ":user/x")));
    }

    private static Map<String, String> principalCtx(String principalArn) {
        return Map.of(
                "aws:principalarn", principalArn,
                "aws:principalaccount", ACCOUNT);
    }
}
