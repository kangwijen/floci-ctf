package io.github.hectorvent.floci.services.backup;

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
 * {@code backup:DescribeBackupVault} scoped to one vault ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class BackupIamScopedIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String ALLOWED_VAULT = "allowed-vault";
    private static final String DECOY_VAULT = "other-vault";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "backup-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "backup");

        createVault(rootAuth, ALLOWED_VAULT);
        createVault(rootAuth, DECOY_VAULT);

        String allowedArn = "arn:aws:backup:" + REGION + ":" + ACCOUNT + ":backup-vault:" + ALLOWED_VAULT;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"backup:DescribeBackupVault",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "describe-one-vault", policy);
    }

    @Test
    void describeAllowedVault() {
        given()
                .header("Authorization", playerBackupAuth())
        .when()
                .get("/backup-vaults/" + ALLOWED_VAULT)
        .then()
                .statusCode(200)
                .body("BackupVaultName", equalTo(ALLOWED_VAULT));
    }

    @Test
    void describeDecoyVaultDenied() {
        given()
                .header("Authorization", playerBackupAuth())
        .when()
                .get("/backup-vaults/" + DECOY_VAULT)
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void createVault(String auth, String vaultName) {
        given()
                .header("Authorization", auth)
                .contentType("application/json")
                .body("{}")
        .when()
                .put("/backup-vaults/" + vaultName)
        .then()
                .statusCode(200)
                .body("BackupVaultName", equalTo(vaultName));
    }

    private String playerBackupAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "backup");
    }
}
