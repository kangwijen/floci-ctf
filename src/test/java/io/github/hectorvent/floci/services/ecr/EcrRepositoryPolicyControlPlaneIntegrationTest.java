package io.github.hectorvent.floci.services.ecr;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * {@code ecr:DescribeRepositories} allowed by repository resource policy alone (no identity policy).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EcrRepositoryPolicyControlPlaneIntegrationTest {

    private static final String CT = "application/x-amz-json-1.1";
    private static final String PREFIX = "AmazonEC2ContainerRegistry_V20150921.";
    private static final String REPO = "policy-only-repo";
    private static final String PRIVATE_REPO = "private-ecr-repo";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;
    private String repoArn;

    @BeforeAll
    void provision() {
        RestAssuredJsonUtils.configureAwsContentTypes();
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        String user = "ecr-policy-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootEcr = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "ecr");

        repoArn = given()
                .header("X-Amz-Target", PREFIX + "CreateRepository")
                .header("Authorization", rootEcr)
                .contentType(CT)
                .body("""
                    { "repositoryName": "%s" }
                    """.formatted(REPO))
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("repository.repositoryArn");

        String userArn = "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":user/" + user;
        String repoPolicy = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"ecr:DescribeRepositories","Resource":"%s"}]}
            """.formatted(userArn, repoArn).trim();

        try {
            String setPolicyBody = new ObjectMapper().writeValueAsString(
                    Map.of("repositoryName", REPO, "policyText", repoPolicy));
            given()
                    .header("X-Amz-Target", PREFIX + "SetRepositoryPolicy")
                    .header("Authorization", rootEcr)
                    .contentType(CT)
                    .body(setPolicyBody)
                    .when().post("/")
                    .then().statusCode(200);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        given()
                .header("X-Amz-Target", PREFIX + "CreateRepository")
                .header("Authorization", rootEcr)
                .contentType(CT)
                .body("""
                    { "repositoryName": "%s" }
                    """.formatted(PRIVATE_REPO))
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void describeRepositoryAllowedByResourcePolicyOnly() {
        given()
                .header("X-Amz-Target", PREFIX + "DescribeRepositories")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "ecr"))
                .contentType(CT)
                .body("""
                    { "repositoryNames": ["%s"] }
                    """.formatted(REPO))
                .when().post("/")
                .then()
                .statusCode(200)
                .body("repositories[0].repositoryName", org.hamcrest.Matchers.equalTo(REPO));
    }

    @Test
    void describeRepositoryDeniedWithoutResourcePolicyAllow() {
        given()
                .header("X-Amz-Target", PREFIX + "DescribeRepositories")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(playerAkid, "ecr"))
                .contentType(CT)
                .body("""
                    { "repositoryNames": ["%s"] }
                    """.formatted(PRIVATE_REPO))
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }
}
