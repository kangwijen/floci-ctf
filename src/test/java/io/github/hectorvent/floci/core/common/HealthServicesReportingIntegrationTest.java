package io.github.hectorvent.floci.core.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(HealthServicesReportingIntegrationTest.DisabledServicesProfile.class)
class HealthServicesReportingIntegrationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Inject
    ServiceRegistry serviceRegistry;

    @Test
    void getServicesOmitsDisabledServices() {
        Map<String, String> services = serviceRegistry.getServices();
        assertFalse(services.containsKey("lambda"));
        assertFalse(services.containsKey("ssm"));
        assertFalse(services.containsKey("sqs"));
        assertTrue(services.containsKey("s3"));
        assertEquals("running", services.get("s3"));
    }

    @Test
    void healthEndpointOmitsDisabledServices() throws Exception {
        String body = given()
                .when()
                .get("/_floci/health")
                .then()
                .statusCode(200)
                .body("services.s3", equalTo("running"))
                .extract()
                .body()
                .asString();

        JsonNode services = MAPPER.readTree(body).get("services");
        assertFalse(services.has("lambda"), "disabled lambda must not appear in health");
        assertFalse(services.has("ssm"), "disabled ssm must not appear in health");
        assertFalse(services.has("sqs"), "disabled sqs must not appear in health");
    }

    public static final class DisabledServicesProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.lambda.enabled", "false",
                    "floci.services.ssm.enabled", "false",
                    "floci.services.sqs.enabled", "false");
        }
    }
}
