package io.github.hectorvent.floci.services.codebuild;

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
import static org.hamcrest.Matchers.hasSize;

/**
 * {@code codebuild:BatchGetProjects} scoped to one project ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CodeBuildIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "CodeBuild_20161006.";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedProject;
    private String decoyProject;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "codebuild-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "codebuild");

        allowedProject = "allowed-build";
        decoyProject = "other-build";
        createProject(rootAuth, allowedProject);
        createProject(rootAuth, decoyProject);

        String allowedArn = "arn:aws:codebuild:" + REGION + ":" + ACCOUNT + ":project/" + allowedProject;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"codebuild:BatchGetProjects",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "batch-get-one-project", policy);
    }

    @Test
    void batchGetAllowedProject() {
        given()
                .header("Authorization", playerCodeBuildAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "BatchGetProjects")
                .contentType(CT)
                .body("{\"names\":[\"" + allowedProject + "\"]}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("projects", hasSize(1))
                .body("projects[0].name", equalTo(allowedProject));
    }

    @Test
    void batchGetDecoyProjectDenied() {
        given()
                .header("Authorization", playerCodeBuildAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "BatchGetProjects")
                .contentType(CT)
                .body("{\"names\":[\"" + decoyProject + "\"]}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void createProject(String auth, String name) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateProject")
                .contentType(CT)
                .body("""
                        {
                          "name": "%s",
                          "source": {"type": "NO_SOURCE"},
                          "artifacts": {"type": "NO_ARTIFACTS"},
                          "environment": {
                            "type": "LINUX_CONTAINER",
                            "image": "aws/codebuild/standard:7.0",
                            "computeType": "BUILD_GENERAL1_SMALL"
                          },
                          "serviceRole": "arn:aws:iam::000000000000:role/codebuild-role"
                        }
                        """.formatted(name))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("project.name", equalTo(name));
    }

    private String playerCodeBuildAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "codebuild");
    }
}
