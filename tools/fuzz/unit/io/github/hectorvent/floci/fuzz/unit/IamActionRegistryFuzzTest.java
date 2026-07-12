package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

/**
 * Property fuzz for {@link IamActionRegistry} route/action resolution.
 */
class IamActionRegistryFuzzTest {

    private static final IamActionRegistry REGISTRY = FuzzFixtures.iamActionRegistry();

    @Property(tries = 80)
    void resolveNeverThrowsError(
            @ForAll("scopes") String scope,
            @ForAll("methods") String method,
            @ForAll @StringLength(max = 120) String path,
            @ForAll @StringLength(max = 200) String body) throws Exception {
        String normalized = path.isEmpty() ? "/" : (path.startsWith("/") ? path : "/" + path);
        ContainerRequestContext ctx = FuzzRequestContexts.formBody(method, normalized, body);
        String seed = scope + "|" + method + "|" + normalized + "|" + body;
        CrashWatchdog.run("IamActionRegistry.resolve", seed, 2000, () -> {
            SecurityOracle.runCatching("IamActionRegistry.resolve", seed,
                    () -> REGISTRY.resolve(scope, ctx));
            return null;
        });
    }

    @Property(tries = 50)
    void restRouteScopeNeverMapsPrefixedInternalToS3(
            @ForAll("methods") String method,
            @ForAll("internalPaths") String path) {
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(method, path, new MultivaluedHashMap<>());
        String scope = REGISTRY.resolveRestRouteScope(ctx);
        if ("s3".equals(scope) && (path.startsWith("/_floci") || path.startsWith("/_localstack")
                || path.startsWith("/_aws") || path.startsWith("/oauth2")
                || path.startsWith("/cognito-idp"))) {
            SecurityOracle.failSecurity(
                    "IamActionRegistry.resolveRestRouteScope",
                    method + " " + path,
                    "internal/oauth path resolved as s3",
                    java.util.Map.of("scope", String.valueOf(scope)));
        }
    }

    @Property(tries = 40)
    void s3ListBucketVersionsKeepsVersionsAction() {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("versions", "");
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery("GET", "/my-bucket", query);
        String action = REGISTRY.resolve("s3", ctx);
        if (action != null && !action.equals("s3:ListBucketVersions") && !action.equals("s3:ListBucket")) {
            // Only flag clear mis-maps away from list APIs.
            if (action.contains("Put") || action.contains("Delete") || action.contains("Create")) {
                SecurityOracle.failSecurity(
                        "IamActionRegistry.s3.versions",
                        "GET /my-bucket?versions",
                        "versions query mapped to mutating action",
                        java.util.Map.of("action", action));
            }
        }
    }

    @Property(tries = 40)
    void json11TargetScopeRejectsBlankTargets(@ForAll @StringLength(max = 80) String target) {
        String scope = REGISTRY.resolveJson11TargetCredentialScope(target);
        if (target == null || target.isBlank() || !target.contains(".")) {
            if (scope != null) {
                SecurityOracle.failSecurity(
                        "IamActionRegistry.json11",
                        String.valueOf(target),
                        "blank/invalid target produced a scope",
                        java.util.Map.of("scope", scope));
            }
        }
    }

    @Provide
    Arbitrary<String> scopes() {
        return Arbitraries.of(FuzzRequestContexts.sampleScopes());
    }

    @Provide
    Arbitrary<String> methods() {
        return Arbitraries.of("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH");
    }

    @Provide
    Arbitrary<String> internalPaths() {
        return Arbitraries.of(
                "/_floci/health",
                "/_floci/state/reset",
                "/_localstack/health",
                "/_aws/cloudformation/ready",
                "/cognito-idp/oauth2/token");
    }
}
