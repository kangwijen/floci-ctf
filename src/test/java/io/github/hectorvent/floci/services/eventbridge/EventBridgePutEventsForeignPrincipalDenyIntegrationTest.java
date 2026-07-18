package io.github.hectorvent.floci.services.eventbridge;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * Bus policy Principal for a foreign account must not authorize a default-account IAM user
 * for {@code events:PutEvents} under CTF IAM enforcement.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class EventBridgePutEventsForeignPrincipalDenyIntegrationTest {

    private static final String JSON_11 = "application/x-amz-json-1.1";
    private static final String FOREIGN_ACCOUNT = "111122223333";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String busName;

    @BeforeAll
    void provision() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        String user = "eb-foreign-principal-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        busName = "foreign-principal-bus-" + UUID.randomUUID().toString().substring(0, 8);
        String rootEvents = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "events");

        given()
                .contentType(JSON_11)
                .header("X-Amz-Target", "AWSEvents.CreateEventBus")
                .header("Authorization", rootEvents)
                .body("{\"Name\":\"" + busName + "\"}")
                .when().post("/")
                .then().statusCode(200);

        given()
                .contentType(JSON_11)
                .header("X-Amz-Target", "AWSEvents.PutPermission")
                .header("Authorization", rootEvents)
                .body("""
                        {
                          "EventBusName": "%s",
                          "Action": "events:PutEvents",
                          "Principal": "%s",
                          "StatementId": "foreign-only"
                        }
                        """.formatted(busName, FOREIGN_ACCOUNT))
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void putEventsDeniedWhenBusPolicyAllowsOnlyForeignAccount() {
        String auth = CtfLabIamTestSupport.scopedAuth(playerAkid, "events");
        given()
                .contentType(JSON_11)
                .header("X-Amz-Target", "AWSEvents.PutEvents")
                .header("Authorization", auth)
                .body("""
                        {
                          "Entries": [{
                            "Source": "floci.ctf",
                            "DetailType": "foreign-principal-deny",
                            "Detail": "{\\"k\\":\\"v\\"}",
                            "EventBusName": "%s"
                          }]
                        }
                        """.formatted(busName))
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
