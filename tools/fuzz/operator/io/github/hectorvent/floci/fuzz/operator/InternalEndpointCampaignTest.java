package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Live campaign: internal operator routes must not succeed for unsigned participants.
 *
 * <p>Skipped unless {@code -Pfuzz-operator} and {@code AWS_ENDPOINT_URL} are set.
 * Optional {@code FUZZ_PARTICIPANT_ACCESS_KEY_ID} / {@code FUZZ_PARTICIPANT_SECRET_ACCESS_KEY}
 * headers must still not reach injection or reset endpoints.
 */
class InternalEndpointCampaignTest {

    private static final String INJECTION_BODY = """
            {"region":"us-east-1","event":{"eventName":"FuzzProbe","eventSource":"fuzz.amazonaws.com"}}\
            """;

    @Test
    void unsignedFlociHealthHiddenOrDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        probeMustNotSucceed(oracle, "Internal.unsigned.health", "GET", "/_floci/health", null, Map.of());
    }

    @Test
    void unsignedStateResetHiddenOrDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        probeMustNotSucceed(oracle, "Internal.unsigned.reset", "POST", "/_floci/state/reset", "{}", Map.of());
    }

    @Test
    void unsignedCloudTrailInjectionHiddenOrDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        probeMustNotSucceed(
                oracle,
                "Internal.unsigned.cloudtrail",
                "POST",
                "/_floci/cloudtrail/events",
                INJECTION_BODY,
                Map.of("Content-Type", "application/json"));
    }

    @Test
    void participantCloudTrailInjectionStillDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        Map<String, String> headers = participantHeaders();
        Assumptions.assumeFalse(headers.isEmpty(), "Set FUZZ_PARTICIPANT_* to run participant probe");
        headers.put("Content-Type", "application/json");
        probeMustNotSucceed(
                oracle,
                "Internal.participant.cloudtrail",
                "POST",
                "/_floci/cloudtrail/events",
                INJECTION_BODY,
                headers);
    }

    @Test
    void participantStateResetStillDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        Map<String, String> headers = participantHeaders();
        Assumptions.assumeFalse(headers.isEmpty(), "Set FUZZ_PARTICIPANT_* to run participant probe");
        headers.put("Content-Type", "application/json");
        probeMustNotSucceed(
                oracle,
                "Internal.participant.reset",
                "POST",
                "/_floci/state/reset",
                "{}",
                headers);
    }

    @Property(tries = 15)
    void unsignedInternalMutatingPathsStayHiddenOrDenied(@ForAll("internalMutatingPaths") String path)
            throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String method = path.contains("cloudtrail") || path.contains("reset") || path.contains("init")
                ? "POST"
                : "GET";
        String body = "POST".equals(method) ? "{}" : null;
        Map<String, String> headers = "POST".equals(method)
                ? Map.of("Content-Type", "application/json")
                : Map.of();
        CrashWatchdog.run("Internal.unsigned.mutating", path, 5000, () -> {
            probeMustNotSucceed(oracle, "Internal.unsigned.mutating", method, path, body, headers);
            return null;
        });
    }

    @Property(tries = 10)
    void unsignedPrefixedInternalPathsStayHiddenOrDenied(@ForAll("prefixedInternalPaths") String path)
            throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        CrashWatchdog.run("Internal.unsigned.prefixed", path, 5000, () -> {
            probeMustNotSucceed(oracle, "Internal.unsigned.prefixed", "GET", path, null, Map.of());
            return null;
        });
    }

    private static void probeMustNotSucceed(
            DifferentialHttpOracle oracle,
            String target,
            String method,
            String path,
            String body,
            Map<String, String> headers) throws Exception {
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(method, path, headers, body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    target,
                    path,
                    "internal endpoint succeeded for non-operator caller",
                    Map.of(
                            "method", method,
                            "status", String.valueOf(result.status()),
                            "body", result.bodySnippet()));
        }
    }

    private static Map<String, String> participantHeaders() {
        String akid = firstNonBlank(
                System.getenv("FUZZ_PARTICIPANT_ACCESS_KEY_ID"),
                System.getProperty("fuzz.participant.accessKeyId"));
        String secret = firstNonBlank(
                System.getenv("FUZZ_PARTICIPANT_SECRET_ACCESS_KEY"),
                System.getProperty("fuzz.participant.secretAccessKey"));
        if (akid == null || secret == null) {
            return Map.of();
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(
                "Authorization",
                "AWS4-HMAC-SHA256 Credential="
                        + akid
                        + "/20260101/us-east-1/execute-api/aws4_request, "
                        + "SignedHeaders=host;x-amz-date, "
                        + "Signature=deadbeef");
        String session = firstNonBlank(
                System.getenv("FUZZ_PARTICIPANT_SESSION_TOKEN"),
                System.getProperty("fuzz.participant.sessionToken"));
        if (session != null) {
            headers.put("X-Amz-Security-Token", session);
        }
        return headers;
    }

    private static DifferentialHttpOracle requireOracle() {
        Optional<DifferentialHttpOracle> maybe = DifferentialHttpOracle.fromEnv();
        Assumptions.assumeTrue(maybe.isPresent(),
                "Set AWS_ENDPOINT_URL and -Pfuzz-operator to run internal endpoint campaigns");
        return maybe.get();
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    @Provide
    Arbitrary<String> internalMutatingPaths() {
        List<String> paths = CorpusLoader.orFallback(
                "paths/internal-mutating.txt",
                List.of(
                        "/_floci/state/reset",
                        "/_floci/cloudtrail/events",
                        "/_floci/cloudtrail/events/batch",
                        "/_localstack/init",
                        "/_aws/cloudformation/ready"));
        return Arbitraries.of(paths);
    }

    @Provide
    Arbitrary<String> prefixedInternalPaths() {
        return Arbitraries.of(
                "/_floci/health",
                "/_localstack/health",
                "/_localstack/init",
                "/_aws/cloudformation/ready");
    }
}
