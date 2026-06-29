package io.github.hectorvent.floci.services.iam;

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
 * Regression: kinesis-scoped SigV4 cannot reach API Gateway v2 control plane.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class IamKinesisCatchAllRouteScopeIntegrationTest {

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-kinesis-catchall";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);
        CtfLabIamTestSupport.putUserPolicy(user, "kinesis-only", """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"kinesis:*","Resource":"*"},
              {"Effect":"Deny","Action":"apigatewayv2:*","Resource":"*"}
            ]}""");
    }

    @Test
    void kinesisScopedPostV2ApisDeniedDespiteKinesisAllow() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "kinesis"))
                .contentType("application/json")
                .body("{\"name\":\"collision-api\",\"protocolType\":\"HTTP\"}")
        .when()
                .post("/v2/apis")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }
}
