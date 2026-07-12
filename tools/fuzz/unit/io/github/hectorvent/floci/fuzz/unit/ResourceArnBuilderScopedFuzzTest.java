package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzCredentialScopes;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import jakarta.ws.rs.container.ContainerRequestContext;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

/**
 * Scoped ARN namespace oracles across {@link FuzzCredentialScopes#allArnBuilderScopes()}.
 */
class ResourceArnBuilderScopedFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();

    @Property(tries = 50)
    void shapedBodyArnStaysInExpectedServiceNamespace(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 24) String name) throws Exception {
        String body = FuzzBodyGenerators.jsonForScope(scope, name);
        ContainerRequestContext ctx = requestForScope(scope, body);
        String seed = scope + "|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.scoped", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.scoped", seed,
                        () -> BUILDER.build(scope, ctx, REGION, ACCOUNT)));
        assertArnNamespace(scope, arn, seed);
    }

    @Property(tries = 40)
    void buildNeverThrowsErrorForShapedBodies(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String name) throws Exception {
        String body = FuzzBodyGenerators.jsonForScope(scope, name);
        ContainerRequestContext ctx = requestForScope(scope, body);
        String seed = scope + "|" + body;
        CrashWatchdog.run("ResourceArnBuilder.scoped.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("ResourceArnBuilder.scoped.crash", seed,
                    () -> BUILDER.build(scope, ctx, REGION, ACCOUNT));
            return null;
        });
    }

    private static ContainerRequestContext requestForScope(String scope, String body) {
        if ("iam".equals(scope) || "sts".equals(scope) || "cloudformation".equals(scope)) {
            return FuzzRequestContexts.formBody("POST", "/", body);
        }
        return FuzzRequestContexts.jsonBody("POST", "/", body);
    }

    private static void assertArnNamespace(String scope, String arn, String seed) {
        if (arn == null) {
            return;
        }
        if ("*".equals(arn) || arn.contains("*")) {
            return;
        }
        String expected = FuzzCredentialScopes.expectedArnService(scope);
        if (expected == null) {
            return;
        }
        // sts:AssumeRole scopes the role ARN (iam:), not an sts: resource.
        boolean ok = arn.contains(":" + expected + ":")
                || arn.startsWith("arn:aws:" + expected)
                || ("sts".equals(scope) && (arn.contains(":iam:") || arn.startsWith("arn:aws:iam")));
        if (!ok) {
            SecurityOracle.failSecurity(
                    "ResourceArnBuilder.scoped",
                    seed,
                    "ARN missing expected service namespace " + expected,
                    java.util.Map.of("arn", arn, "scope", scope));
        }
    }

    @Provide
    Arbitrary<String> scopes() {
        return Arbitraries.of(FuzzCredentialScopes.allArnBuilderScopes());
    }
}
