package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.StringLength;

/**
 * SigV4 parser/validator fuzz: malformed auth must not crash; wrong secrets must not validate.
 */
class SigV4RequestValidatorFuzzTest {

    @Property(tries = 80)
    void validateNeverThrowsErrorOnGarbage(
            @ForAll @StringLength(max = 200) String method,
            @ForAll @StringLength(max = 200) String path,
            @ForAll @StringLength(max = 400) String query,
            @ForAll @StringLength(max = 400) String authHeader,
            @ForAll @StringLength(max = 80) String secret) throws Exception {
        String seed = method + "|" + path + "|" + query + "|" + authHeader;
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("authorization", authHeader);
        headers.add("host", "localhost:4566");
        CrashWatchdog.run("SigV4RequestValidator.validate", seed, 2000, () -> {
            SecurityOracle.runCatching("SigV4RequestValidator.validate", seed, () ->
                    SigV4RequestValidator.validate(
                            method.isBlank() ? "GET" : method,
                            path.isBlank() ? "/" : path,
                            query,
                            headers,
                            authHeader == null ? "" : authHeader,
                            secret.isBlank() ? "secret" : secret,
                            new byte[0]));
            return null;
        });
    }

    @Property(tries = 40)
    void incompleteAuthorizationNeverValid(
            @ForAll @StringLength(min = 8, max = 40) String secret) {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        String auth = "AWS4-HMAC-SHA256 Credential=AKIATEST/20200101/us-east-1/s3/aws4_request, "
                + "SignedHeaders=host, Signature=deadbeef";
        headers.add("authorization", auth);
        headers.add("host", "localhost:4566");
        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                "GET",
                "/bucket/key",
                "",
                headers,
                auth,
                secret,
                new byte[0]);
        if (result == SigV4RequestValidator.Result.VALID) {
            SecurityOracle.failSecurity(
                    "SigV4RequestValidator.incomplete",
                    secret,
                    "incomplete SigV4 header accepted as valid",
                    java.util.Map.of());
        }
    }

    @Property(tries = 60)
    void parseAccessKeyIdNeverThrows(@ForAll @StringLength(max = 200) String credential) {
        SecurityOracle.runCatching("SigV4RequestValidator.parseAccessKeyId", credential, () ->
                SigV4RequestValidator.parseAccessKeyIdFromCredential(credential));
    }
}
