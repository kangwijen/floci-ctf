package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import jakarta.ws.rs.container.ContainerRequestContext;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

import java.util.List;
import java.util.Locale;

/**
 * Multi-table PartiQL ExecuteStatement ARN extraction.
 */
class ResourceArnBuilderPartiqlFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();

    @Property(tries = 40)
    void partiqlJoinMentionsBothTablesInArnList(
            @ForAll @AlphaChars @StringLength(min = 2, max = 16) String tableA,
            @ForAll @AlphaChars @StringLength(min = 2, max = 16) String tableB) throws Exception {
        String a = tableA.toLowerCase(Locale.ROOT);
        String b = tableB.toLowerCase(Locale.ROOT);
        if (a.equals(b)) {
            b = b + "x";
        }
        String body = FuzzBodyGenerators.partiqlJoin(a, b);
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = body;
        List<String> arns = CrashWatchdog.run("ResourceArnBuilder.partiql", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.partiql", seed,
                        () -> BUILDER.buildAllDynamoDbExecuteStatementPartiQLResources(
                                ctx, REGION, ACCOUNT)));
        if (arns == null) {
            return;
        }
        String joined = String.join(",", arns);
        if (!joined.contains(a) || !joined.contains(b)) {
            SecurityOracle.failSecurity(
                    "ResourceArnBuilder.partiql",
                    seed,
                    "JOIN PartiQL ARNs missing one or both table names",
                    java.util.Map.of("arns", joined, "a", a, "b", b));
        }
        for (String arn : arns) {
            if (arn != null && !arn.contains(":dynamodb:") && !"*".equals(arn)) {
                SecurityOracle.failSecurity(
                        "ResourceArnBuilder.partiql",
                        seed,
                        "PartiQL ARN left dynamodb namespace",
                        java.util.Map.of("arn", arn));
            }
        }
    }

    @Property(tries = 30)
    void partiqlBuildNeverThrowsError(
            @ForAll @AlphaChars @StringLength(min = 1, max = 12) String tableA,
            @ForAll @AlphaChars @StringLength(min = 1, max = 12) String tableB) throws Exception {
        String body = FuzzBodyGenerators.partiqlJoin(tableA, tableB);
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = body;
        CrashWatchdog.run("ResourceArnBuilder.partiql.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("ResourceArnBuilder.partiql.crash", seed, () -> {
                BUILDER.buildAllDynamoDbExecuteStatementPartiQLResources(ctx, REGION, ACCOUNT);
                BUILDER.build("dynamodb", ctx, REGION, ACCOUNT);
                return null;
            });
            return null;
        });
    }
}
