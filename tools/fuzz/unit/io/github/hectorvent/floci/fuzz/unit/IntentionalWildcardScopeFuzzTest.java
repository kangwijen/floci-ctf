package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
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
 * Documented intentional {@code *} scopes must not invent a fake service ARN namespace.
 */
class IntentionalWildcardScopeFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();

    @Property(tries = 40)
    void buildReturnsWildcardForIntentionalScopes(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 24) String name) throws Exception {
        String body = "{\"Name\":\"" + name + "\",\"ResourceArn\":\"arn:aws:s3:::fuzz-" + name + "\"}";
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = scope + "|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.intentionalWildcard", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.intentionalWildcard", seed,
                        () -> BUILDER.build(scope, ctx, REGION, ACCOUNT)));
        assertIntentionalWildcard(arn, scope, seed);
    }

    @Property(tries = 30)
    void buildFromJsonBodyReturnsWildcardForIntentionalScopes(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String name) throws Exception {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("Name", name);
        body.put("ResourceArn", "arn:aws:s3:::fuzz-" + name);
        String seed = scope + "|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.intentionalWildcard.json", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.intentionalWildcard.json", seed,
                        () -> BUILDER.buildFromJsonBody(scope, body, REGION, ACCOUNT)));
        assertIntentionalWildcard(arn, scope, seed);
    }

    private static void assertIntentionalWildcard(String arn, String scope, String seed) {
        if (!"*".equals(arn)) {
            SecurityOracle.failSecurity(
                    "ResourceArnBuilder.intentionalWildcard",
                    seed,
                    "intentional wildcard scope must return *",
                    java.util.Map.of("scope", scope, "arn", String.valueOf(arn)));
        }
    }

    @Provide
    Arbitrary<String> scopes() {
        return Arbitraries.of(FuzzCredentialScopes.intentionalWildcardScopes());
    }
}
