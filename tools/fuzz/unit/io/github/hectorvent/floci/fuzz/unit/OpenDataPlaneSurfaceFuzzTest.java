package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzCredentialScopes;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.neptune.proxy.NeptuneGremlinProxy;
import jakarta.ws.rs.container.ContainerRequestContext;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

import java.util.List;
import java.util.Map;

/**
 * Neptune Gremlin and DocumentDB Mongo wire protocols are intentional transparent TCP relays under CTF.
 * SigV4 material in WebSocket upgrade headers is relayed, not validated on the data plane.
 * HTTP IAM for control-plane APIs still scopes {@code neptune} to the RDS ARN namespace and
 * {@code docdb} remains catalog-only with {@code rds} alias mapping.
 */
class OpenDataPlaneSurfaceFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();

    @Property(tries = 30)
    void neptuneArnStaysRdsNamespaced(
            @ForAll @AlphaChars @StringLength(min = 1, max = 24) String name) throws Exception {
        String body = FuzzBodyGenerators.jsonForScope("neptune", name);
        ContainerRequestContext ctx = FuzzRequestContexts.formBody("POST", "/", body);
        String seed = "neptune|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.neptune.openDataPlane", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.neptune.openDataPlane", seed,
                        () -> BUILDER.build("neptune", ctx, REGION, ACCOUNT)));
        assertRdsNamespace(arn, "neptune", seed);
    }

    @Property(tries = 30)
    void docdbCatalogScopeStaysRdsOrWildcard(
            @ForAll @AlphaChars @StringLength(min = 1, max = 24) String name) throws Exception {
        String body = FuzzBodyGenerators.jsonForScope("docdb", name);
        ContainerRequestContext ctx = FuzzRequestContexts.formBody("POST", "/", body);
        String seed = "docdb|" + body;
        String arn = CrashWatchdog.run("ResourceArnBuilder.docdb.openDataPlane", seed, 2000, () ->
                SecurityOracle.runCatching("ResourceArnBuilder.docdb.openDataPlane", seed,
                        () -> BUILDER.build("docdb", ctx, REGION, ACCOUNT)));
        if (arn == null || "*".equals(arn)) {
            return;
        }
        assertRdsNamespace(arn, "docdb", seed);
    }

    @Property(tries = 20)
    void neptuneProxyLifecycleNeverThrowsError(
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String clusterId,
            @ForAll @StringLength(max = 80) String host) throws Exception {
        String seed = clusterId + "|" + host;
        CrashWatchdog.run("NeptuneGremlinProxy.stop", seed, 1000, () -> {
            SecurityOracle.runCatching("NeptuneGremlinProxy.stop", seed, () -> {
                NeptuneGremlinProxy proxy = new NeptuneGremlinProxy(clusterId, safeHost(host), 1);
                proxy.stop();
                return Boolean.TRUE;
            });
            return null;
        });
    }

    @Property(tries = 15)
    void corpusUpgradeSamplesNeverThrowError(@ForAll("upgradeSamples") String sample) throws Exception {
        String seed = sample.length() > 120 ? sample.substring(0, 120) : sample;
        CrashWatchdog.run("OpenDataPlane.corpus", seed, 1000, () -> {
            SecurityOracle.runCatching("OpenDataPlane.corpus", seed, () -> {
                if (sample.isBlank()) {
                    return Boolean.TRUE;
                }
                for (String scope : FuzzCredentialScopes.openDataPlaneTcpScopes()) {
                    ContainerRequestContext ctx = FuzzRequestContexts.formBody(
                            "POST", "/", "Action=DescribeDBInstances&DBInstanceIdentifier=fuzz");
                    BUILDER.build(scope, ctx, REGION, ACCOUNT);
                }
                return Boolean.TRUE;
            });
            return null;
        });
    }

    @Provide
    Arbitrary<String> upgradeSamples() {
        List<String> samples = CorpusLoader.orFallback("tcp/neptune-docdb-notes.txt", List.of(
                "GET /gremlin HTTP/1.1",
                "Upgrade: websocket",
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="));
        return Arbitraries.of(samples);
    }

    private static void assertRdsNamespace(String arn, String scope, String seed) {
        if (!arn.contains(":rds:")) {
            SecurityOracle.failSecurity(
                    "OpenDataPlane.arnNamespace",
                    seed,
                    "open data-plane scope must stay in rds ARN namespace for HTTP IAM",
                    Map.of("scope", scope, "arn", arn));
        }
    }

    private static String safeHost(String host) {
        if (host == null || host.isBlank()) {
            return "127.0.0.1";
        }
        return host.replaceAll("[^a-zA-Z0-9.\\-]", "").isBlank() ? "127.0.0.1" : host;
    }
}
