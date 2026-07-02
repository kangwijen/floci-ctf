package io.github.hectorvent.floci.services.ecr;

import io.github.hectorvent.floci.testing.DockerTestSupport;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.QuarkusTestProfile;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestMethodOrder;

import java.util.concurrent.TimeUnit;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end ECR control plane against a real {@code registry:2} sidecar.
 * Verifies that host {@code docker push} bytes are visible via {@code ListImages}
 * and {@code BatchGetImage}.
 */
@QuarkusTest
@TestProfile(EcrDockerPushIntegrationTest.PathStyleRegistryProfile.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EcrDockerPushIntegrationTest {

    private static final String CT = "application/x-amz-json-1.1";
    private static final String PREFIX = "AmazonEC2ContainerRegistry_V20150921.";
    private static final String TAG = "v1";

    private String repo;
    private String repositoryUri;

    @BeforeAll
    void configureRestAssured() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        Assumptions.assumeTrue(DockerTestSupport.isDockerAvailable(),
                "Docker daemon must be available for ECR docker push integration tests");
        repo = "floci-it/push-" + System.currentTimeMillis();
    }

    @Test
    @Order(1)
    void createRepositoryAndDockerPush() throws Exception {
        repositoryUri = given()
            .header("X-Amz-Target", PREFIX + "CreateRepository")
            .contentType(CT)
            .body("""
                { "repositoryName": "%s" }
                """.formatted(repo))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("repository.repositoryName", equalTo(repo))
            .body("repository.repositoryUri", not(empty()))
            .extract().jsonPath().getString("repository.repositoryUri");

        String imageRef = repositoryUri + ":" + TAG;
        runDocker("pull", "alpine:3.19");
        runDocker("tag", "alpine:3.19", imageRef);
        runDocker("push", imageRef);
    }

    @Test
    @Order(2)
    void listImagesAfterDockerPush() {
        given()
            .header("X-Amz-Target", PREFIX + "ListImages")
            .contentType(CT)
            .body("""
                { "repositoryName": "%s" }
                """.formatted(repo))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("imageIds.size()", equalTo(1))
            .body("imageIds[0].imageTag", equalTo(TAG));
    }

    @Test
    @Order(3)
    void batchGetImageAfterDockerPush() {
        given()
            .header("X-Amz-Target", PREFIX + "BatchGetImage")
            .contentType(CT)
            .body("""
                {
                  "repositoryName": "%s",
                  "imageIds": [ { "imageTag": "%s" } ]
                }
                """.formatted(repo, TAG))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("images.size()", equalTo(1))
            .body("images[0].imageId.imageTag", equalTo(TAG))
            .body("images[0].imageManifest", not(empty()));
    }

    @Test
    @Order(4)
    void deleteRepositoryForce() {
        given()
            .header("X-Amz-Target", PREFIX + "DeleteRepository")
            .contentType(CT)
            .body("""
                { "repositoryName": "%s", "force": true }
                """.formatted(repo))
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("repository.repositoryName", equalTo(repo));
    }

    private static void runDocker(String... args) throws Exception {
        String[] command = new String[args.length + 1];
        command[0] = "docker";
        System.arraycopy(args, 0, command, 1, args.length);
        Process process = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes());
        assertTrue(process.waitFor(120, TimeUnit.SECONDS),
                "docker command timed out: " + String.join(" ", command));
        assertEquals(0, process.exitValue(),
                "docker " + String.join(" ", args) + " failed: " + output);
    }

    /**
     * Path-style URIs ({@code localhost:5100/account/region/repo}) avoid
     * {@code *.localhost} hostname resolution gaps on some Docker Desktop hosts.
     */
    public static final class PathStyleRegistryProfile implements QuarkusTestProfile {

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.ecr.uri-style", "path",
                    "floci.services.ecr.registry-base-port", "5100",
                    "floci.services.ecr.registry-max-port", "5100");
        }
    }
}
