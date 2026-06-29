package io.github.hectorvent.floci.services.route53;

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
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code route53:GetHostedZone} scoped to one hosted zone ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class Route53IamScopedIntegrationTest {

    private static final String XML = "application/xml";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedZoneId;
    private String decoyZoneId;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "route53-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "route53");

        allowedZoneId = createHostedZone(rootAuth, "allowed.example.com", "allowed-zone-ref");
        decoyZoneId = createHostedZone(rootAuth, "decoy.example.com", "other-zone-ref");

        String allowedArn = "arn:aws:route53:::hostedzone/" + allowedZoneId;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"route53:GetHostedZone",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "get-one-zone", policy);
    }

    @Test
    void getAllowedHostedZone() {
        given()
                .header("Authorization", playerRoute53Auth())
        .when()
                .get("/2013-04-01/hostedzone/" + allowedZoneId)
        .then()
                .statusCode(200)
                .contentType(XML)
                .body("GetHostedZoneResponse.HostedZone.Id", equalTo("/hostedzone/" + allowedZoneId))
                .body("GetHostedZoneResponse.HostedZone.Name", equalTo("allowed.example.com."));
    }

    @Test
    void getDecoyHostedZoneDenied() {
        given()
                .header("Authorization", playerRoute53Auth())
        .when()
                .get("/2013-04-01/hostedzone/" + decoyZoneId)
        .then()
                .statusCode(403);
    }

    private static String createHostedZone(String auth, String name, String callerRef) {
        String body = """
                <?xml version="1.0" encoding="UTF-8"?>
                <CreateHostedZoneRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
                  <Name>%s</Name>
                  <CallerReference>%s</CallerReference>
                </CreateHostedZoneRequest>
                """.formatted(name, callerRef);

        String locationHeader = given()
                .header("Authorization", auth)
                .contentType(XML)
                .body(body)
        .when()
                .post("/2013-04-01/hostedzone")
        .then()
                .statusCode(201)
                .header("Location", containsString("/2013-04-01/hostedzone/Z"))
                .extract().header("Location");

        return locationHeader.substring(locationHeader.lastIndexOf('/') + 1);
    }

    private String playerRoute53Auth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "route53");
    }
}
