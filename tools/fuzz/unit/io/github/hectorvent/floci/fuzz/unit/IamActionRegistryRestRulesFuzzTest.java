package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

/**
 * REST route scope rules must not mis-map internal or Cognito paths to {@code s3}.
 */
class IamActionRegistryRestRulesFuzzTest {

    private static final IamActionRegistry REGISTRY = FuzzFixtures.iamActionRegistry();

    @Property(tries = 50)
    void highValueRestPathsNeverMapProtectedPrefixesToS3(
            @ForAll("methods") String method,
            @ForAll("restPaths") String path) {
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(
                method, path, new MultivaluedHashMap<>());
        String scope = REGISTRY.resolveRestRouteScope(ctx);
        if ("s3".equals(scope) && isProtectedFromS3(path)) {
            SecurityOracle.failSecurity(
                    "IamActionRegistry.restRules",
                    method + " " + path,
                    "protected path resolved as s3",
                    java.util.Map.of("scope", String.valueOf(scope)));
        }
    }

    @Property(tries = 40)
    void resolveRestRouteScopeNeverThrowsError(
            @ForAll("methods") String method,
            @ForAll("restPaths") String path) throws Exception {
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(
                method, path, new MultivaluedHashMap<>());
        String seed = method + "|" + path;
        CrashWatchdog.run("IamActionRegistry.restRules.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("IamActionRegistry.restRules.crash", seed,
                    () -> REGISTRY.resolveRestRouteScope(ctx));
            return null;
        });
    }

    @Property(tries = 30)
    void lambdaScopeResolveOnLambdaPathsNeverThrows(
            @ForAll("methods") String method,
            @ForAll("lambdaPaths") String path) throws Exception {
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(
                method, path, new MultivaluedHashMap<>());
        String seed = method + "|" + path;
        CrashWatchdog.run("IamActionRegistry.restRules.lambda", seed, 2000, () -> {
            SecurityOracle.runCatching("IamActionRegistry.restRules.lambda", seed,
                    () -> REGISTRY.resolve("lambda", ctx));
            return null;
        });
    }

    private static boolean isProtectedFromS3(String path) {
        String p = path == null ? "" : (path.startsWith("/") ? path : "/" + path);
        return p.startsWith("/_floci")
                || p.startsWith("/_localstack")
                || p.startsWith("/_aws")
                || p.startsWith("/cognito-idp")
                || "/health".equals(p);
    }

    @Provide
    Arbitrary<String> methods() {
        return Arbitraries.of("GET", "POST");
    }

    @Provide
    Arbitrary<String> restPaths() {
        return Arbitraries.of(FuzzBodyGenerators.highValueRestPaths());
    }

    @Provide
    Arbitrary<String> lambdaPaths() {
        return Arbitraries.of(
                "/2015-03-31/functions",
                "/2015-03-31/functions/fn/invocations",
                "/lambda-url/fn");
    }
}
