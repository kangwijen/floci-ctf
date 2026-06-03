package io.github.hectorvent.floci.core.common;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

@QuarkusTest
@TestProfile(CtfHideInternalEndpointsIntegrationTest.PrefixedProfile.class)
class CtfHideInternalEndpointsIntegrationTest {

    @Test
    void prefixedModeHidesFlociRoutesButKeepsHealth() {
        given().when().get("/_floci/health").then().statusCode(404);
        given().when().get("/_localstack/info").then().statusCode(404);
        given().when().post("/_floci/ecr/gc").then().statusCode(404);

        given().when().get("/health").then().statusCode(200).body("services.s3", equalTo("running"));
    }

    public static final class PrefixedProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("floci.ctf.hide-internal-endpoints", "true");
        }
    }
}
