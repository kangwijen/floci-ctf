package io.github.hectorvent.floci.services.rdsdata;

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
 * {@code rds-data:ExecuteStatement} scoped to one RDS cluster ARN in {@code resourceArn}.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RdsDataIamScopedIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String ALLOWED_CLUSTER = "arn:aws:rds:" + REGION + ":" + ACCOUNT + ":cluster:allowed-db";
    private static final String DECOY_CLUSTER = "arn:aws:rds:" + REGION + ":" + ACCOUNT + ":cluster:decoy-db";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-rdsdata-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"rds-data:ExecuteStatement",
               "Resource":"%s"}
            ]}""".formatted(ALLOWED_CLUSTER);
        CtfLabIamTestSupport.putUserPolicy(user, "execute-one-cluster", policy);
    }

    @Test
    void executeOnAllowedClusterPassesIam() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "rds-data"))
                .contentType("application/json")
                .body("""
                        {
                          "resourceArn": "%s",
                          "secretArn": "arn:aws:secretsmanager:%s:%s:secret:unused",
                          "database": "app",
                          "sql": "select 1"
                        }
                        """.formatted(ALLOWED_CLUSTER, REGION, ACCOUNT))
        .when()
                .post("/Execute")
        .then()
                .statusCode(400);
    }

    @Test
    void executeOnDecoyClusterDenied() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "rds-data"))
                .contentType("application/json")
                .body("""
                        {
                          "resourceArn": "%s",
                          "secretArn": "arn:aws:secretsmanager:%s:%s:secret:unused",
                          "database": "app",
                          "sql": "select 1"
                        }
                        """.formatted(DECOY_CLUSTER, REGION, ACCOUNT))
        .when()
                .post("/Execute")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }
}
