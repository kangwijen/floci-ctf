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
 * Catalog-only scopes (no {@code ResourceArnBuilder} arm) must not throw Errors and must not
 * invent unrelated ARN namespaces.
 */
class CatalogOnlyScopeFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();

    @Property(tries = 50)
    void buildNeverThrowsError(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 24) String name) throws Exception {
        String body = "{\"Name\":\"" + name + "\",\"clusterName\":\"" + name + "\"}";
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = scope + "|" + body;
        CrashWatchdog.run("ResourceArnBuilder.catalogOnly.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("ResourceArnBuilder.catalogOnly.crash", seed,
                    () -> BUILDER.build(scope, ctx, REGION, ACCOUNT));
            return null;
        });
    }

    @Property(tries = 40)
    void buildReturnsWildcardOrNamespacedArn(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String name) throws Exception {
        String body = "{\"Name\":\"" + name + "\",\"ResourceArn\":\"arn:aws:s3:::fuzz-" + name + "\"}";
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = scope + "|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.catalogOnly", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.catalogOnly", seed,
                        () -> BUILDER.build(scope, ctx, REGION, ACCOUNT)));
        assertCatalogOnlyArn(scope, arn, seed);
    }

    @Property(tries = 30)
    void buildFromJsonBodyNeverThrowsError(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String name) throws Exception {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("Name", name);
        String seed = scope + "|" + body;
        CrashWatchdog.run("ResourceArnBuilder.catalogOnly.json.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("ResourceArnBuilder.catalogOnly.json.crash", seed,
                    () -> BUILDER.buildFromJsonBody(scope, body, REGION, ACCOUNT));
            return null;
        });
    }

    @Property(tries = 30)
    void buildFromJsonBodyReturnsWildcardOrNamespacedArn(
            @ForAll("scopes") String scope,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String name) throws Exception {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("Name", name);
        String seed = scope + "|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.catalogOnly.json", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.catalogOnly.json", seed,
                        () -> BUILDER.buildFromJsonBody(scope, body, REGION, ACCOUNT)));
        assertCatalogOnlyArn(scope, arn, seed);
    }

    private static void assertCatalogOnlyArn(String scope, String arn, String seed) {
        if (arn == null || "*".equals(arn)) {
            return;
        }
        String expected = FuzzCredentialScopes.expectedArnService(scope);
        if (expected == null) {
            if (arn.startsWith("arn:aws:")) {
                SecurityOracle.failSecurity(
                        "ResourceArnBuilder.catalogOnly",
                        seed,
                        "catalog-only scope invented ARN without expectedArnService mapping",
                        java.util.Map.of("scope", scope, "arn", arn));
            }
            return;
        }
        boolean ok = arn.contains(":" + expected + ":") || arn.startsWith("arn:aws:" + expected);
        if (!ok) {
            SecurityOracle.failSecurity(
                    "ResourceArnBuilder.catalogOnly",
                    seed,
                    "catalog-only scope produced unrelated ARN namespace",
                    java.util.Map.of("scope", scope, "arn", arn, "expected", expected));
        }
    }

    @Provide
    Arbitrary<String> scopes() {
        return Arbitraries.of(FuzzCredentialScopes.catalogOnlyScopes());
    }
}
