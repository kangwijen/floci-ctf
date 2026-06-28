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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;

@QuarkusTest
@TestProfile(CloudTrailEventInjectionIntegrationTest.Profile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CloudTrailEventInjectionIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String INJECT_PATH = "/_floci/cloudtrail/events";
    private static final String BATCH_PATH = "/_floci/cloudtrail/events/batch";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    CloudTrailEventStore eventStore;

    @Inject
    ObjectMapper objectMapper;

    @BeforeAll
    void bindRestAssured() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
    }

    @BeforeEach
    void resetStore() {
        eventStore.clear();
    }

    @Test
    void operatorRootCanInjectEventVisibleInLookupEvents() throws Exception {
        String eventTime = "2026-03-15T14:30:00.000Z";
        String eventName = "ConsoleLogin";
        String body = objectMapper.writeValueAsString(Map.of(
                "region", REGION,
                "preserveEventTime", true,
                "deliverToTrails", false,
                "event", sampleEvent(eventName, eventTime, "203.0.113.50")));

        postSigned(INJECT_PATH, body)
                .statusCode(200)
                .body("eventId", notNullValue())
                .body("eventTime", equalTo(eventTime));

        var lookup = eventStore.lookup(
                REGION, null, null, List.of(
                        new CloudTrailEventStore.LookupAttribute("EventName", eventName)),
                10, null);
        assertEquals(1, lookup.events().size());
        assertEquals(eventName, lookup.events().get(0).getEventName());
        assertEquals(eventTime, CloudTrailEventRecorder.formatEventTime(lookup.events().get(0).getEventTime()));
    }

    @Test
    void batchInjectionPreservesSuppliedTimesAndOrder() throws Exception {
        String earlier = "2026-03-10T08:00:00.000Z";
        String later = "2026-03-10T08:00:00.500Z";
        String body = objectMapper.writeValueAsString(Map.of(
                "region", REGION,
                "preserveEventTime", true,
                "deliverToTrails", false,
                "events", List.of(
                        sampleEvent("DeleteBucket", later, "198.51.100.10"),
                        sampleEvent("CreateBucket", earlier, "198.51.100.11"))));

        postSigned(BATCH_PATH, body)
                .statusCode(200)
                .body("events", hasSize(2));

        var lookup = eventStore.lookup(REGION, null, null, null, 10, null);
        assertEquals(2, lookup.events().size());
        assertEquals("DeleteBucket", lookup.events().get(0).getEventName());
        assertEquals("CreateBucket", lookup.events().get(1).getEventName());
        assertEquals(later, CloudTrailEventRecorder.formatEventTime(lookup.events().get(0).getEventTime()));
        assertEquals(earlier, CloudTrailEventRecorder.formatEventTime(lookup.events().get(1).getEventTime()));
    }

    @Test
    void playerCredentialsAreForbidden() throws Exception {
        String formBody = "Action=CreateUser&UserName=inject-denied-player";
        SigV4HttpTestSupport.SignedHeaders createUserSigned = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET,
                REGION,
                "iam",
                formBody,
                Instant.now());
        given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", createUserSigned.authorization())
                .header("x-amz-date", createUserSigned.amzDate())
                .header("x-amz-content-sha256", createUserSigned.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(formBody)
        .when()
                .post("/")
        .then()
                .statusCode(200);

        String keyForm = "Action=CreateAccessKey&UserName=inject-denied-player";
        SigV4HttpTestSupport.SignedHeaders createKeySigned = SigV4HttpTestSupport.signFormPost(
                endpoint.getHost(),
                endpoint.getPort(),
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET,
                REGION,
                "iam",
                keyForm,
                Instant.now());
        var keyResponse = given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", createKeySigned.authorization())
                .header("x-amz-date", createKeySigned.amzDate())
                .header("x-amz-content-sha256", createKeySigned.contentSha256())
                .contentType("application/x-www-form-urlencoded; charset=ISO-8859-1")
                .body(keyForm)
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .extract().xmlPath();
        String playerKey = keyResponse.getString(
                "CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
        String playerSecret = keyResponse.getString(
                "CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.SecretAccessKey");

        String body = objectMapper.writeValueAsString(Map.of(
                "region", REGION,
                "event", sampleEvent("PutObject", "2026-03-15T10:00:00.000Z", "10.0.0.1")));

        Instant now = Instant.now();
        SigV4HttpTestSupport.SignedRestHeaders signed = SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                INJECT_PATH,
                body.getBytes(StandardCharsets.UTF_8),
                playerKey,
                playerSecret,
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
                .statusCode(403);
    }

    private io.restassured.response.ValidatableResponse postSigned(String path, String body) throws Exception {
        Instant now = Instant.now();
        SigV4HttpTestSupport.SignedRestHeaders signed = SigV4HttpTestSupport.signRestPost(
                endpoint.getHost(),
                endpoint.getPort(),
                path,
                body.getBytes(StandardCharsets.UTF_8),
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                CtfLabIamEnforcementProfile.ROOT_SECRET,
                REGION,
                "floci",
                now);

        return given()
                .header("Host", endpoint.getHost() + ":" + endpoint.getPort())
                .header("Authorization", signed.authorization())
                .header("x-amz-date", signed.amzDate())
                .header("x-amz-content-sha256", signed.contentSha256())
                .contentType("application/json")
                .body(body)
        .when()
                .post(path)
        .then();
    }

    private static Map<String, Object> sampleEvent(String eventName, String eventTime, String sourceIp) {
        Map<String, Object> identity = new LinkedHashMap<>();
        identity.put("type", "IAMUser");
        identity.put("userName", "suspicious-user");
        identity.put("arn", "arn:aws:iam::000000000000:user/suspicious-user");
        identity.put("accountId", "000000000000");

        Map<String, Object> event = new LinkedHashMap<>();
        event.put("eventVersion", "1.08");
        event.put("eventName", eventName);
        event.put("eventSource", "s3.amazonaws.com");
        event.put("eventTime", eventTime);
        event.put("awsRegion", REGION);
        event.put("sourceIPAddress", sourceIp);
        event.put("userIdentity", identity);
        event.put("readOnly", false);
        event.put("eventType", "AwsApiCall");
        event.put("managementEvent", true);
        event.put("eventCategory", "Management");
        return event;
    }

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.ofEntries(
                    Map.entry("floci.services.iam.enforcement-enabled", "true"),
                    Map.entry("floci.services.iam.strict-enforcement-enabled", "true"),
                    Map.entry("floci.auth.validate-signatures", "true"),
                    Map.entry("floci.auth.root-access-key-id", CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID),
                    Map.entry("floci.auth.root-secret-access-key", CtfLabIamEnforcementProfile.ROOT_SECRET),
                    Map.entry("floci.ctf.hide-internal-endpoints", "false"),
                    Map.entry("floci.ctf.cloud-trail-injection-enabled", "true"),
                    Map.entry("floci.services.cloudtrail.enabled", "true"),
                    Map.entry("floci.services.cloudtrail.audit-enabled", "true"));
        }
    }
}
