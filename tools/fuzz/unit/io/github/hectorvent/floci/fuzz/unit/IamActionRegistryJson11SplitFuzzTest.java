package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON 1.1 {@code X-Amz-Target} credential-scope resolution (catalog may be empty).
 */
class IamActionRegistryJson11SplitFuzzTest {

    private static final IamActionRegistry REGISTRY = FuzzFixtures.iamActionRegistry();

    @Property(tries = 50)
    void resolveJson11TargetNeverThrows(@ForAll("targets") String target) throws Exception {
        String seed = String.valueOf(target);
        CrashWatchdog.run("IamActionRegistry.json11Split", seed, 2000, () -> {
            SecurityOracle.runCatching("IamActionRegistry.json11Split", seed,
                    () -> REGISTRY.resolveJson11TargetCredentialScope(target));
            return null;
        });
    }

    @Property(tries = 40)
    void blankOrInvalidTargetNeverProducesScope(
            @ForAll @StringLength(max = 80) String target) {
        String scope = REGISTRY.resolveJson11TargetCredentialScope(target);
        if (target == null || target.isBlank() || !target.contains(".")) {
            if (scope != null) {
                SecurityOracle.failSecurity(
                        "IamActionRegistry.json11Split.blank",
                        String.valueOf(target),
                        "blank/invalid target produced a scope",
                        java.util.Map.of("scope", scope));
            }
        }
    }

    @Property(tries = 30)
    void dynamoDbPrefixedTargetsDoNotCrash(
            @ForAll @StringLength(min = 1, max = 40) String suffix) throws Exception {
        String target = "DynamoDB_20120810." + suffix.replace('.', '_');
        String seed = target;
        CrashWatchdog.run("IamActionRegistry.json11Split.dynamodb", seed, 2000, () -> {
            // Empty catalog mock may return null; that is acceptable.
            SecurityOracle.runCatching("IamActionRegistry.json11Split.dynamodb", seed,
                    () -> REGISTRY.resolveJson11TargetCredentialScope(target));
            return null;
        });
    }

    @Provide
    Arbitrary<String> targets() {
        List<String> seeds = new ArrayList<>(FuzzBodyGenerators.highValueJson11Targets());
        seeds.addAll(CorpusLoader.orFallback("paths/internal.txt", List.of()));
        seeds.add("");
        seeds.add(".");
        seeds.add("NoDot");
        seeds.add("DynamoDB_20120810.GetItem");
        seeds.add("DynamoDB_20120810.ExecuteStatement");
        return Arbitraries.of(seeds);
    }
}
