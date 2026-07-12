package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.PolicyPrincipalMatcher;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

import java.util.List;
import java.util.Map;

/**
 * Policy evaluation and principal-matching security oracles.
 */
class IamPolicyAndPrincipalFuzzTest {

    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final IamPolicyEvaluator EVALUATOR = new IamPolicyEvaluator(MAPPER);
    private static final String ACCOUNT = "111122223333";
    private static final String ROOT_ARN = "arn:aws:iam::" + ACCOUNT + ":root";
    private static final String USER_ARN = "arn:aws:iam::" + ACCOUNT + ":user/reader";

    private static final String DENY_S3 = """
            {
              "Version": "2012-10-17",
              "Statement": [{
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::secret-bucket/*"
              }]
            }
            """;

    @Property(tries = 30)
    void explicitDenyBeatsAllowStar() {
        CallerContext caller = new CallerContext(
                List.of("""
                        {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}
                        """, DENY_S3),
                null,
                null);
        IamPolicyEvaluator.Decision decision = EVALUATOR.evaluate(
                caller,
                List.of(),
                "s3:GetObject",
                "arn:aws:s3:::secret-bucket/key",
                Map.of());
        SecurityOracle.expectDeny(
                decision == IamPolicyEvaluator.Decision.ALLOW,
                "IamPolicyEvaluator.explicitDeny",
                "deny+allow*",
                "explicit Deny must win over Allow *");
    }

    @Property(tries = 50)
    void resourcePolicyAccountRootDoesNotAuthorizeIamUser(
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String userName) throws Exception {
        String userArn = "arn:aws:iam::" + ACCOUNT + ":user/" + userName;
        JsonNode principal = MAPPER.readTree("{\"AWS\":\"" + ROOT_ARN + "\"}");
        boolean matches = PolicyPrincipalMatcher.matchesPrincipalDimension(
                principal, null, userArn, ACCOUNT);
        SecurityOracle.expectNoAuthBypass(
                matches,
                "PolicyPrincipalMatcher.resourceRoot",
                userArn,
                "account :root must not match IAM user on resource policies");
    }

    @Property(tries = 40)
    void trustPolicyAccountRootMayMatchIamUser() throws Exception {
        JsonNode principal = MAPPER.readTree("{\"AWS\":\"" + ROOT_ARN + "\"}");
        boolean matches = PolicyPrincipalMatcher.matchesTrustPrincipalDimension(
                principal, null, USER_ARN, ACCOUNT);
        SecurityOracle.expectAllow(
                matches,
                "PolicyPrincipalMatcher.trustRoot",
                USER_ARN,
                "trust :root should match IAM user in account");
    }

    @Property(tries = 60)
    void malformedPolicyDoesNotThrowError(@ForAll @StringLength(max = 300) String policyDoc) {
        CallerContext caller = new CallerContext(List.of(policyDoc), null, null);
        SecurityOracle.runCatching("IamPolicyEvaluator.malformed", policyDoc, () ->
                EVALUATOR.evaluate(caller, List.of(), "s3:GetObject", "arn:aws:s3:::b/k", Map.of()));
    }

    @Provide
    Arbitrary<String> actions() {
        return Arbitraries.of("s3:GetObject", "s3:PutObject", "sqs:ReceiveMessage", "kms:Decrypt");
    }
}
