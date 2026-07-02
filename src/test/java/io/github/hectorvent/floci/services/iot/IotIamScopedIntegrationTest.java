package io.github.hectorvent.floci.services.iot;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code iot:UpdateThingShadow} scoped to one thing ARN (SigV4 scope {@code iotdata}).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IotIamScopedIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ALLOWED_THING = "allowed-shadow-thing";
    private static final String DECOY_THING = "decoy-shadow-thing";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "iot-shadow-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "iot");

        createThing(rootAuth, ALLOWED_THING);
        createThing(rootAuth, DECOY_THING);

        String allowedArn = "arn:aws:iot:" + REGION + ":" + CtfLabIamEnforcementProfile.ACCOUNT
                + ":thing/" + ALLOWED_THING;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iot:UpdateThingShadow",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "shadow-one-thing", policy);
    }

    @Test
    void updateAllowedThingShadow() {
        updateShadow(playerIotDataAuth(), ALLOWED_THING)
                .statusCode(200);
    }

    @Test
    void updateDecoyThingShadowDenied() {
        updateShadow(playerIotDataAuth(), DECOY_THING)
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void createThing(String auth, String thingName) {
        given()
                .header("Authorization", auth)
                .contentType("application/json")
                .body("{}")
                .when().post("/things/" + thingName)
                .then().statusCode(200);
    }

    private static io.restassured.response.ValidatableResponse updateShadow(String auth, String thingName) {
        return given()
                .header("Authorization", auth)
                .contentType("application/json")
                .body("""
                        {"state":{"reported":{"probe":true}}}
                        """)
                .when().post("/things/" + thingName + "/shadow")
                .then();
    }

    private String playerIotDataAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "iotdata");
    }
}
