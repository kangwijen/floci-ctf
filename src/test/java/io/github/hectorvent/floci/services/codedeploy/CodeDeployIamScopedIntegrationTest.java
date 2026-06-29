package io.github.hectorvent.floci.services.codedeploy;

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
import static org.hamcrest.Matchers.notNullValue;

/**
 * {@code codedeploy:GetDeployment} scoped to one deployment group ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CodeDeployIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "CodeDeploy_20141006.";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    private static final String ALLOWED_APP = "allowed-app";
    private static final String ALLOWED_GROUP = "allowed-dg";
    private static final String DECOY_APP = "other-app";
    private static final String DECOY_GROUP = "other-dg";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedDeploymentId;
    private String decoyDeploymentId;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "codedeploy-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "codedeploy");

        createServerApplication(rootAuth, ALLOWED_APP);
        createServerApplication(rootAuth, DECOY_APP);
        createServerDeploymentGroup(rootAuth, ALLOWED_APP, ALLOWED_GROUP);
        createServerDeploymentGroup(rootAuth, DECOY_APP, DECOY_GROUP);
        allowedDeploymentId = createServerDeployment(rootAuth, ALLOWED_APP, ALLOWED_GROUP);
        decoyDeploymentId = createServerDeployment(rootAuth, DECOY_APP, DECOY_GROUP);

        String allowedArn = "arn:aws:codedeploy:" + REGION + ":" + ACCOUNT
                + ":deploymentgroup:" + ALLOWED_APP + "/" + ALLOWED_GROUP;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"codedeploy:GetDeployment",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "get-one-deployment", policy);
    }

    @Test
    void getAllowedDeployment() {
        given()
                .header("Authorization", playerCodeDeployAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "GetDeployment")
                .contentType(CT)
                .body("""
                        {
                          "deploymentId": "%s",
                          "applicationName": "%s",
                          "deploymentGroupName": "%s"
                        }
                        """.formatted(allowedDeploymentId, ALLOWED_APP, ALLOWED_GROUP))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("deploymentInfo.deploymentId", equalTo(allowedDeploymentId))
                .body("deploymentInfo.applicationName", equalTo(ALLOWED_APP))
                .body("deploymentInfo.deploymentGroupName", equalTo(ALLOWED_GROUP));
    }

    @Test
    void getDecoyDeploymentDenied() {
        given()
                .header("Authorization", playerCodeDeployAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "GetDeployment")
                .contentType(CT)
                .body("""
                        {
                          "deploymentId": "%s",
                          "applicationName": "%s",
                          "deploymentGroupName": "%s"
                        }
                        """.formatted(decoyDeploymentId, DECOY_APP, DECOY_GROUP))
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void createServerApplication(String auth, String appName) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateApplication")
                .contentType(CT)
                .body("""
                        {"applicationName":"%s","computePlatform":"Server"}
                        """.formatted(appName))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("applicationId", notNullValue());
    }

    private static void createServerDeploymentGroup(String auth, String appName, String groupName) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateDeploymentGroup")
                .contentType(CT)
                .body("""
                        {
                          "applicationName": "%s",
                          "deploymentGroupName": "%s",
                          "deploymentConfigName": "CodeDeployDefault.AllAtOnce",
                          "serviceRoleArn": "arn:aws:iam::000000000000:role/CodeDeployRole"
                        }
                        """.formatted(appName, groupName))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("deploymentGroupId", notNullValue());
    }

    private static String createServerDeployment(String auth, String appName, String groupName) {
        String appSpec = """
                os: linux
                hooks:
                  ApplicationStart:
                    - location: scripts/start.sh
                      timeout: 30
                """;
        String escapedAppSpec = appSpec.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");

        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateDeployment")
                .contentType(CT)
                .body("""
                        {
                          "applicationName": "%s",
                          "deploymentGroupName": "%s",
                          "revision": {
                            "revisionType": "AppSpecContent",
                            "appSpecContent": {
                              "content": "%s"
                            }
                          }
                        }
                        """.formatted(appName, groupName, escapedAppSpec))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("deploymentId", notNullValue())
                .extract().jsonPath().getString("deploymentId");
    }

    private String playerCodeDeployAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "codedeploy");
    }
}
