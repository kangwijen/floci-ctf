package io.github.hectorvent.floci.fuzz.unit;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzCredentialScopes;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;

import java.nio.charset.StandardCharsets;

/**
 * Jazzer entry for {@link SigV4RequestValidator}.
 */
class SigV4RequestValidatorJazzerTest {

    private static final String[] METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"};

    @FuzzTest
    void fuzzValidate(FuzzedDataProvider data) {
        final String method = data.pickValue(METHODS);
        String service = data.pickValue(FuzzCredentialScopes.catalogCredentialScopes().toArray(String[]::new));
        String path = data.consumeString(256);
        if (path.isBlank()) {
            path = "/";
        } else if (!path.startsWith("/")) {
            path = "/" + path;
        }
        String query = data.consumeString(512);
        String authHeader = data.consumeString(1024);
        String secret = data.consumeString(128);
        if (secret.isBlank()) {
            secret = "secret";
        }
        String bodyTail = data.consumeRemainingAsString();
        if (bodyTail.length() > 4096) {
            bodyTail = bodyTail.substring(0, 4096);
        }
        final String finalPath = path;
        final String finalQuery = query;
        final String finalAuthHeader = authHeader;
        final String finalSecret = secret;
        final String finalBodyTail = bodyTail;
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("authorization", finalAuthHeader);
        headers.add("host", "localhost:4566");
        headers.add("x-amz-target", service + ".Action");
        String seed = method + "|" + finalPath + "|" + finalAuthHeader;
        byte[] bodyBytes = finalBodyTail.getBytes(StandardCharsets.UTF_8);
        SecurityOracle.runCatching("SigV4RequestValidator.jazzer", seed, () ->
                SigV4RequestValidator.validate(method, finalPath, finalQuery, headers, finalAuthHeader, finalSecret, bodyBytes));
    }
}
