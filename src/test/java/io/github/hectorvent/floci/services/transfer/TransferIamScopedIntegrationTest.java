package io.github.hectorvent.floci.services.transfer;

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
import static org.hamcrest.Matchers.startsWith;

/**
 * {@code transfer:DescribeServer} scoped to one server ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TransferIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "TransferService.";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedServerId;
    private String decoyServerId;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-transfer-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "transfer");

        allowedServerId = createServer(rootAuth);
        decoyServerId = createServer(rootAuth);

        String allowedArn = "arn:aws:transfer:" + REGION + ":" + ACCOUNT + ":server/" + allowedServerId;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"transfer:DescribeServer",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "describe-one-server", policy);
    }

    @Test
    void describeAllowedServer() {
        given()
                .header("Authorization", playerTransferAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeServer")
                .contentType(CT)
                .body("{\"ServerId\":\"" + allowedServerId + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Server.ServerId", equalTo(allowedServerId));
    }

    @Test
    void describeDecoyServerDenied() {
        given()
                .header("Authorization", playerTransferAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeServer")
                .contentType(CT)
                .body("{\"ServerId\":\"" + decoyServerId + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static String createServer(String auth) {
        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateServer")
                .contentType(CT)
                .body("{}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("ServerId", startsWith("s-"))
                .extract().jsonPath().getString("ServerId");
    }

    private String playerTransferAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "transfer");
    }
}
