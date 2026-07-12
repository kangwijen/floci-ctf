package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

/**
 * Credential-smuggling and incomplete SigV4 Authorization must never validate as {@code VALID}.
 */
class SigV4CredentialSmugglingFuzzTest {

    @Property(tries = 50)
    void authorizationWithoutAws4PrefixNeverValid(
            @ForAll("smuggledAuth") String authHeader,
            @ForAll @StringLength(min = 8, max = 40) String secret) throws Exception {
        if (authHeader != null && authHeader.trim().startsWith("AWS4-HMAC-SHA256")) {
            return;
        }
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("authorization", authHeader);
        headers.add("host", "localhost:4566");
        String seed = String.valueOf(authHeader);
        SigV4RequestValidator.Result result = CrashWatchdog.run(
                "SigV4.smuggle.prefix", seed, 2000, () ->
                        SecurityOracle.runCatching("SigV4.smuggle.prefix", seed, () ->
                                SigV4RequestValidator.validate(
                                        "GET",
                                        "/bucket/key",
                                        "",
                                        headers,
                                        authHeader == null ? "" : authHeader,
                                        secret,
                                        new byte[0])));
        if (result == SigV4RequestValidator.Result.VALID) {
            SecurityOracle.failSecurity(
                    "SigV4.smuggle.prefix",
                    seed,
                    "Authorization without AWS4-HMAC-SHA256 prefix accepted as VALID",
                    java.util.Map.of());
        }
    }

    @Property(tries = 40)
    void asiaCredentialWithoutSessionTokenIncompleteNeverValid(
            @ForAll @StringLength(min = 8, max = 24) String secret,
            @ForAll @StringLength(min = 8, max = 20) String asiaSuffix) throws Exception {
        String accessKey = "ASIA" + asiaSuffix.replaceAll("[^A-Za-z0-9]", "A");
        String auth = "AWS4-HMAC-SHA256 Credential=" + accessKey
                + "/20200101/us-east-1/s3/aws4_request, "
                + "SignedHeaders=host, Signature=deadbeef";
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("authorization", auth);
        headers.add("host", "localhost:4566");
        // Deliberately omit x-amz-security-token and x-amz-date (incomplete).
        String seed = auth;
        SigV4RequestValidator.Result result = CrashWatchdog.run(
                "SigV4.smuggle.asia", seed, 2000, () ->
                        SecurityOracle.runCatching("SigV4.smuggle.asia", seed, () ->
                                SigV4RequestValidator.validate(
                                        "GET",
                                        "/bucket/key",
                                        "",
                                        headers,
                                        auth,
                                        secret,
                                        new byte[0])));
        if (result == SigV4RequestValidator.Result.VALID) {
            SecurityOracle.failSecurity(
                    "SigV4.smuggle.asia",
                    seed,
                    "incomplete ASIA Authorization accepted as VALID",
                    java.util.Map.of());
        }
    }

    @Property(tries = 40)
    void smuggledAuthNeverThrowsError(
            @ForAll("smuggledAuth") String authHeader,
            @ForAll @StringLength(min = 4, max = 20) String secret) throws Exception {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("authorization", authHeader);
        headers.add("host", "localhost:4566");
        String seed = String.valueOf(authHeader);
        CrashWatchdog.run("SigV4.smuggle.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("SigV4.smuggle.crash", seed, () ->
                    SigV4RequestValidator.validate(
                            "GET",
                            "/",
                            "",
                            headers,
                            authHeader == null ? "" : authHeader,
                            secret,
                            new byte[0]));
            return null;
        });
    }

    @Provide
    Arbitrary<String> smuggledAuth() {
        return Arbitraries.of(
                "Credential=AKIATEST/20200101/us-east-1/s3/aws4_request, "
                        + "SignedHeaders=host, Signature=deadbeef",
                "Bearer AKIATEST",
                "AWS Credential=AKIATEST",
                "AWS4 Credential=AKIATEST/20200101/us-east-1/s3/aws4_request",
                "HMAC-SHA256 Credential=AKIATEST/20200101/us-east-1/s3/aws4_request, "
                        + "SignedHeaders=host, Signature=00",
                "AWS4-HMAC-SHA256Credential=AKIATEST/20200101/us-east-1/s3/aws4_request, "
                        + "SignedHeaders=host, Signature=deadbeef",
                "",
                "null",
                "Basic dGVzdDp0ZXN0");
    }
}
