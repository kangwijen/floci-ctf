package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzCredentialScopes;
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
 * Thin REST services (batch, amazonmq, s3vectors) must not be mis-mapped to {@code s3}.
 */
class ThinRestServicePathFuzzTest {

    private static final IamActionRegistry REGISTRY = FuzzFixtures.iamActionRegistry();

    @Property(tries = 50)
    void thinRestPathsNeverResolveToS3(
            @ForAll("methods") String method,
            @ForAll("thinRestPaths") String path) {
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(
                method, path, new MultivaluedHashMap<>());
        String scope = REGISTRY.resolveRestRouteScope(ctx);
        if ("s3".equals(scope)) {
            SecurityOracle.failSecurity(
                    "IamActionRegistry.thinRest",
                    method + " " + path,
                    "thin REST service path resolved as s3",
                    java.util.Map.of("scope", scope));
        }
    }

    @Property(tries = 40)
    void resolveRestRouteScopeNeverThrowsError(
            @ForAll("methods") String method,
            @ForAll("thinRestPaths") String path) throws Exception {
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(
                method, path, new MultivaluedHashMap<>());
        String seed = method + "|" + path;
        CrashWatchdog.run("IamActionRegistry.thinRest.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("IamActionRegistry.thinRest.crash", seed,
                    () -> REGISTRY.resolveRestRouteScope(ctx));
            return null;
        });
    }

    @Provide
    Arbitrary<String> methods() {
        return Arbitraries.of("GET", "POST", "PUT", "DELETE");
    }

    @Provide
    Arbitrary<String> thinRestPaths() {
        return Arbitraries.of(FuzzCredentialScopes.thinRestServicePaths());
    }
}
