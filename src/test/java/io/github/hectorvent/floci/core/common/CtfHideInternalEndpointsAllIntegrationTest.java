package io.github.hectorvent.floci.core.common;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;

@QuarkusTest
@TestProfile(CtfHideInternalEndpointsAllIntegrationTest.AllHiddenProfile.class)
class CtfHideInternalEndpointsAllIntegrationTest {

    @Test
    void allModeHidesHealthAndPrefixedRoutes() {
        given().when().get("/health").then().statusCode(404);
        given().when().get("/_floci/health").then().statusCode(404);
        given().when().get("/_localstack/info").then().statusCode(404);
    }

    public static final class AllHiddenProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.ctf.hide-internal-endpoints", "all");
        }
    }
}
