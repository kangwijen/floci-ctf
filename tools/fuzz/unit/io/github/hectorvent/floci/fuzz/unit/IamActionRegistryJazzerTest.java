package io.github.hectorvent.floci.fuzz.unit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;

/**
 * Jazzer entry for {@link IamActionRegistry}.
 */
class IamActionRegistryJazzerTest {

    private static final IamActionRegistry REGISTRY = FuzzFixtures.iamActionRegistry();
    private static final String[] METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"};
    private static final String DEFAULT_JSON11_TARGET = "DynamoDB_20120810.GetItem";

    @FuzzTest
    void fuzzResolve(FuzzedDataProvider data) {
        int mode = data.consumeInt(0, 2);
        switch (mode) {
            case 0 -> {
                String scope = data.pickValue(FuzzRequestContexts.sampleScopes().toArray(String[]::new));
                String method = data.pickValue(METHODS);
                String path = cap(data.consumeString(512));
                String body = cap(data.consumeRemainingAsString());
                path = normalizePath(path);
                ContainerRequestContext ctx = FuzzRequestContexts.formBody(method, path, body);
                String seed = scope + "|" + method + "|" + path + "|" + body;
                SecurityOracle.runCatching("IamActionRegistry.jazzer.resolve", seed,
                        () -> REGISTRY.resolve(scope, ctx));
            }
            case 1 -> {
                String method = data.pickValue(METHODS);
                String path = cap(data.consumeRemainingAsString());
                path = normalizePath(path);
                ContainerRequestContext ctx = FuzzRequestContexts.withQuery(method, path, new MultivaluedHashMap<>());
                String seed = method + "|" + path;
                SecurityOracle.runCatching("IamActionRegistry.jazzer.restRoute", seed,
                        () -> REGISTRY.resolveRestRouteScope(ctx));
            }
            default -> {
                String target = cap(data.consumeRemainingAsString());
                if (target.isBlank()) {
                    target = DEFAULT_JSON11_TARGET;
                }
                final String json11Target = target;
                SecurityOracle.runCatching("IamActionRegistry.jazzer.json11", json11Target,
                        () -> REGISTRY.resolveJson11TargetCredentialScope(json11Target));
            }
        }
    }

    private static String cap(String value) {
        if (value == null) {
            return "";
        }
        return value.length() > 4096 ? value.substring(0, 4096) : value;
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }
}
