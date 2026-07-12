package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * HTTP differential campaign against a live CTF Compose instance.
 *
 * <p>Skipped unless {@code -Pfuzz-operator} and {@code AWS_ENDPOINT_URL} (or
 * {@code fuzz.endpoint}) are set.
 */
class HttpDifferentialCampaignTest {

    private static Optional<DifferentialHttpOracle> live() {
        if (Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true"))) {
            return Optional.empty();
        }
        return DifferentialHttpOracle.fromEnv();
    }

    @Test
    void unsignedStsGetCallerIdentityDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of("Content-Type", "application/x-www-form-urlencoded"),
                "Action=GetCallerIdentity&Version=2011-06-15");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Http.unsigned.sts",
                    "GetCallerIdentity",
                    "unsigned STS GetCallerIdentity succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
        oracle.assertUnsignedDeniedAndParticipantNeverSucceeds(
                "Http.signed.sts",
                "POST",
                "/",
                Map.of("Content-Type", "application/x-www-form-urlencoded; charset=ISO-8859-1"),
                "Action=GetCallerIdentity&Version=2011-06-15",
                "us-east-1",
                "sts");
    }

    @Test
    void unsignedS3ListBucketsDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "GET", "/", Map.of(), null);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Http.unsigned.s3",
                    "GET /",
                    "unsigned ListBuckets succeeded under CTF profile",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedJson11SecretsDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String body = "{\"SecretId\":\"flag\"}";
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "secretsmanager.GetSecretValue"),
                body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Http.unsigned.secrets",
                    "GetSecretValue",
                    "unsigned Secrets Manager call succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
        oracle.assertUnsignedDeniedAndParticipantNeverSucceeds(
                "Http.signed.secrets",
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "secretsmanager.GetSecretValue"),
                body,
                "us-east-1",
                "secretsmanager");
    }

    @Test
    void internalFlociPathHiddenOrDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "GET", "/_floci/health", Map.of(), null);
        if (result.status() == 200) {
            SecurityOracle.failSecurity(
                    "Http.internal.hide",
                    "/_floci/health",
                    "internal path returned 200 under CTF hide mode",
                    Map.of());
        }
    }

    @Property(tries = 20)
    void unsignedMutatedQueryActionsStayDenied(
            @ForAll("queryActions") String action,
            @ForAll @StringLength(max = 40) String noise) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String body = "Action=" + action + "&Version=2010-05-08&Noise=" + noise;
        CrashWatchdog.run("Http.unsigned.query", body, 5000, () -> {
            DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                    "POST",
                    "/",
                    Map.of("Content-Type", "application/x-www-form-urlencoded"),
                    body);
            if (result.success()) {
                SecurityOracle.failSecurity(
                        "Http.unsigned.query",
                        body,
                        "unsigned query action succeeded",
                        Map.of("status", String.valueOf(result.status()), "action", action));
            }
            return null;
        });
    }

    @Property(tries = 15)
    void unsignedJson11TargetsStayDenied(@ForAll("jsonTargets") String target) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", target),
                "{}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "Http.unsigned.json11",
                    target,
                    "unsigned JSON 1.1 call succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Property(tries = 10)
    void unsignedRestPathsStayDenied(@ForAll("restPaths") String path) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange("GET", path, Map.of(), null);
        if (result.success() && !"/health".equals(path)) {
            SecurityOracle.failSecurity(
                    "Http.unsigned.rest",
                    path,
                    "unsigned REST path succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    private static DifferentialHttpOracle requireOracle() {
        Optional<DifferentialHttpOracle> maybe = live();
        Assumptions.assumeTrue(maybe.isPresent(),
                "Set AWS_ENDPOINT_URL and -Pfuzz-operator to run HTTP campaigns");
        return maybe.get();
    }

    @Provide
    Arbitrary<String> queryActions() {
        List<String> actions = CorpusLoader.orFallback(
                "query/actions.txt", FuzzBodyGenerators.highValueQueryActions());
        return Arbitraries.of(actions);
    }

    @Provide
    Arbitrary<String> jsonTargets() {
        List<String> targets = CorpusLoader.orFallback(
                "json11/targets.txt", FuzzBodyGenerators.highValueJson11Targets());
        return Arbitraries.of(targets);
    }

    @Provide
    Arbitrary<String> restPaths() {
        List<String> paths = CorpusLoader.orFallback(
                "paths/rest.txt", FuzzBodyGenerators.highValueRestPaths());
        return Arbitraries.of(paths);
    }
}
