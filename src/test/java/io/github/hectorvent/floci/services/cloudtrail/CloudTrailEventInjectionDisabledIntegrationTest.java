package io.github.hectorvent.floci.services.cloudtrail;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.SigV4HttpTestSupport;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

@QuarkusTest
@TestProfile(CloudTrailEventInjectionDisabledIntegrationTest.Profile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloudTrailEventInjectionDisabledIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String INJECT_PATH = "/_floci/cloudtrail/events";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    void bindRestAssured() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
    }

    @Test
    void injectionDisabledReturnsNotFound() throws Exception {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventName", "StopLogging");
        event.put("eventSource", "cloudtrail.amazonaws.com");
        event.put("eventTime", "2026-03-15T10:00:00.000Z");
        String body = objectMapper.writeValueAsString(Map.of("region", REGION, "event", event));

        Instant now = Instant.now();
        SigV4HttpTestSupport.SignedRestHeaders signed = SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                INJECT_PATH,
                body.getBytes(StandardCharsets.UTF_8),
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET,
                REGION,
                "floci",
                now);

        given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/json")
                .body(body)
        .when()
                .post(INJECT_PATH)
        .then()
                .statusCode(404);
    }

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.ofEntries(
                    Map.entry("floci.auth.validate-signatures", "true"),
                    Map.entry("floci.auth.root-access-key-id", CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID),
                    Map.entry("floci.auth.root-secret-access-key", CtfLabIamEnforcementProfile.ROOT_SECRET),
                    Map.entry("floci.ctf.hide-internal-endpoints", "false"),
                    Map.entry("floci.ctf.cloud-trail-injection-enabled", "false"));
        }
    }
}
