package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryRouteResolver;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.ws.rs.container.ContainerRequestContext;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Docker Distribution {@code /v2/*} route resolution must stay crash-free and must not
 * mis-route registry paths to unrelated IAM REST scopes (e.g. {@code s3}).
 */
class EcrRegistryPathFuzzTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String HOST = ACCOUNT + ".dkr.ecr." + REGION + ".localhost:5100";

    private static final EcrRegistryRouteResolver HOSTNAME_RESOLVER =
            FuzzFixtures.ecrRegistryRouteResolver("hostname");
    private static final EcrRegistryRouteResolver PATH_RESOLVER =
            FuzzFixtures.ecrRegistryRouteResolver("path");
    private static final IamActionRegistry IAM_REGISTRY = FuzzFixtures.iamActionRegistry();

    @Property(tries = 60)
    void resolveNeverThrowsError(
            @ForAll("methods") String method,
            @ForAll("ecrPaths") String path,
            @ForAll("hosts") String host,
            @ForAll boolean pathUriStyle) throws Exception {
        EcrRegistryRouteResolver resolver = pathUriStyle ? PATH_RESOLVER : HOSTNAME_RESOLVER;
        String seed = method + "|" + path + "|" + host + "|pathStyle=" + pathUriStyle;
        CrashWatchdog.run("EcrRegistry.resolve", seed, 2000, () -> {
            SecurityOracle.runCatching("EcrRegistry.resolve", seed, () ->
                    resolver.resolve(
                            method,
                            path,
                            host,
                            pathUriStyle && PATH_RESOLVER.usesPathUriStyle()));
            return null;
        });
    }

    @Property(tries = 40)
    void v2DockerPathsDoNotResolveRestScopeToS3(
            @ForAll("methods") String method,
            @ForAll("ecrPaths") String path) {
        if (!path.startsWith("/v2/")) {
            return;
        }
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(method, path, null);
        String scope = IAM_REGISTRY.resolveRestRouteScope(ctx);
        if ("s3".equals(scope)) {
            SecurityOracle.failSecurity(
                    "EcrRegistry.iamScope",
                    method + " " + path,
                    "/v2 registry path resolved as s3 REST scope",
                    Map.of("scope", scope));
        }
    }

    @Property(tries = 30)
    void knownManifestRouteMapsToEcrAction(@ForAll("manifestMethods") String method) {
        String repo = "fuzz-repo";
        String registryPath = "/v2/" + repo + "/manifests/latest";
        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                HOSTNAME_RESOLVER.resolve(method, registryPath, HOST, false);
        if (route.isEmpty() || route.get().iamAction() == null) {
            SecurityOracle.failSecurity(
                    "EcrRegistry.manifest",
                    method + " " + registryPath,
                    "known manifest path did not map to ECR IAM action",
                    Map.of());
        }
        if (!route.get().iamAction().startsWith("ecr:")) {
            SecurityOracle.failSecurity(
                    "EcrRegistry.manifestAction",
                    method + " " + registryPath,
                    "manifest path mapped to non-ecr action",
                    Map.of("action", route.get().iamAction()));
        }
    }

    @Property(tries = 25)
    void pingRouteDoesNotRequireAuth() {
        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                HOSTNAME_RESOLVER.resolve("GET", "/v2/", null, false);
        if (route.isEmpty() || route.get().requiresAuth()) {
            SecurityOracle.failSecurity(
                    "EcrRegistry.ping",
                    "/v2/",
                    "ECR ping route should not require auth",
                    Map.of());
        }
    }

    @Property(tries = 25)
    void nonV2PathsReturnEmpty(
            @ForAll("methods") String method,
            @ForAll("nonEcrPaths") String path) {
        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                HOSTNAME_RESOLVER.resolve(method, path, HOST, false);
        if (route.isPresent() && route.get().iamAction() != null) {
            SecurityOracle.failSecurity(
                    "EcrRegistry.nonV2",
                    method + " " + path,
                    "non-/v2 path resolved to ECR IAM action",
                    Map.of("action", route.get().iamAction()));
        }
    }

    @Property(tries = 30)
    void fuzzedPathSegmentsStayCrashFree(
            @ForAll @StringLength(min = 1, max = 24) String repo,
            @ForAll @StringLength(min = 1, max = 16) String tag,
            @ForAll("methods") String method) throws Exception {
        String sanitizedRepo = repo.replaceAll("[^a-zA-Z0-9._/-]", "r").toLowerCase(Locale.ROOT);
        String sanitizedTag = tag.replaceAll("[^a-zA-Z0-9._:-]", "t");
        String path = "/v2/" + sanitizedRepo + "/manifests/" + sanitizedTag;
        String seed = method + "|" + path;
        CrashWatchdog.run("EcrRegistry.fuzzSegments", seed, 2000, () -> {
            SecurityOracle.runCatching("EcrRegistry.fuzzSegments", seed, () ->
                    HOSTNAME_RESOLVER.resolve(method, path, HOST, false));
            return null;
        });
    }

    @Provide
    Arbitrary<String> methods() {
        return Arbitraries.of("GET", "PUT", "POST", "PATCH", "HEAD", "DELETE");
    }

    @Provide
    Arbitrary<String> manifestMethods() {
        return Arbitraries.of("GET", "HEAD", "PUT", "DELETE");
    }

    @Provide
    Arbitrary<String> hosts() {
        return Arbitraries.of(
                HOST,
                "localhost:4566",
                "localhost:5100",
                "",
                ACCOUNT + ".dkr.ecr." + REGION + ".amazonaws.com",
                "evil.example.com:443");
    }

    @Provide
    Arbitrary<String> ecrPaths() {
        Set<String> all = new LinkedHashSet<>();
        all.addAll(CorpusLoader.orFallback("rest/paths.txt", List.of()));
        all.addAll(List.of(
                "/v2",
                "/v2/",
                "/v2/_catalog",
                "/v2/fuzz-repo/manifests/latest",
                "/v2/fuzz-repo/blobs/sha256:deadbeef",
                "/v2/fuzz-repo/blobs/uploads/",
                "/v2/fuzz-repo/blobs/uploads/uuid",
                "/v2/fuzz-repo/tags/list",
                "/v2/" + ACCOUNT + "/" + REGION + "/fuzz-repo/manifests/latest",
                "/v2/" + ACCOUNT + "/" + REGION + "/fuzz-repo/blobs/sha256:abc",
                "/v2/" + ACCOUNT + "/" + REGION + "/fuzz-repo/tags/list"));
        return Arbitraries.of(new ArrayList<>(all));
    }

    @Provide
    Arbitrary<String> nonEcrPaths() {
        return Arbitraries.of(
                "/health",
                "/_floci/health",
                "/restapis",
                "/v2/apis",
                "/v2/apis/api-id",
                "/2015-03-31/functions",
                "/cognito-idp/oauth2/token",
                "/fuzz-bucket/key");
    }
}
