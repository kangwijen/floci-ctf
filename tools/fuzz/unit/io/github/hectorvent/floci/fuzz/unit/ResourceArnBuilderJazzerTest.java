package io.github.hectorvent.floci.fuzz.unit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import jakarta.ws.rs.container.ContainerRequestContext;

/**
 * Jazzer entry for {@link ResourceArnBuilder}. Runs as regression corpus when
 * {@code JAZZER_FUZZ=0}; mutates when profile {@code fuzz-jazzer} is active.
 */
class ResourceArnBuilderJazzerTest {

    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";

    @FuzzTest
    void fuzzBuild(FuzzedDataProvider data) {
        String scope = data.pickValue(FuzzRequestContexts.sampleScopes().toArray(String[]::new));
        String body = data.consumeRemainingAsString();
        if (body.length() > 4096) {
            body = body.substring(0, 4096);
        }
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = scope + "|" + body;
        SecurityOracle.runCatching("ResourceArnBuilder.jazzer", seed,
                () -> BUILDER.build(scope, ctx, REGION, ACCOUNT));
    }
}
