package io.github.hectorvent.floci.services.ecr.registry;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.github.hectorvent.floci.testing.DockerTestSupport;
import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Registry auth proxy integration: issued tokens authenticate {@code /v2/} ping and IAM
 * resource policies gate manifest reads.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EcrRegistryPolicyDataPlaneIntegrationTest {

    private static final String CT = "application/x-amz-json-1.1";
    private static final String PREFIX = "AmazonEC2ContainerRegistry_V20150921.";
    private static final String REPO = "registry-policy-repo";

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private String playerAkid;
    private String playerAuthToken;
    private String repoArn;
    private int registryPort;

    @BeforeAll
    void provision() throws Exception {
        RestAssuredJsonUtils.configureAwsContentTypes();
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        Assumptions.assumeTrue(DockerTestSupport.isDockerAvailable(),
                "Docker daemon required for ECR registry data plane integration tests");

        String user = "ecr-registry-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        CtfLabIamTestSupport.putUserPolicy(user, "ecr-login", """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"}]}
            """);

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

        String proxyEndpoint = given()
                .header("X-Amz-Target", PREFIX + "GetAuthorizationToken")
                .header("Authorization", rootEcr)
                .contentType(CT)
                .body("{}")
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("authorizationData[0].proxyEndpoint");

        registryPort = URI.create(proxyEndpoint).getPort();
        playerAuthToken = fetchAuthToken(playerAkid);

        String userArn = "arn:aws:iam::" + CtfLabIamEnforcementProfile.ACCOUNT + ":user/" + user;
        String repoPolicy = """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"ecr:BatchGetImage","Resource":"%s"}]}
            """.formatted(userArn, repoArn).trim();

        String setPolicyBody = new ObjectMapper().writeValueAsString(
                Map.of("repositoryName", REPO, "policyText", repoPolicy));
        given()
                .header("X-Amz-Target", PREFIX + "SetRepositoryPolicy")
                .header("Authorization", rootEcr)
                .contentType(CT)
                .body(setPolicyBody)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void registryPingRejectsMissingAuth() throws Exception {
        HttpResponse<String> resp = httpGet("/v2/", null);
        assertEquals(401, resp.statusCode());
    }

    @Test
    void registryPingAcceptsIssuedToken() throws Exception {
        HttpResponse<String> resp = httpGet("/v2/", basicAuthFromToken(playerAuthToken));
        assertEquals(200, resp.statusCode(), resp.body());
    }

    @Test
    void manifestReadAllowedByResourcePolicy() throws Exception {
        String path = "/v2/" + REPO + "/manifests/missing-tag";
        HttpResponse<String> allowed = httpGet(path, basicAuthFromToken(playerAuthToken));
        assertTrue(allowed.statusCode() == 404 || allowed.statusCode() == 405,
                "allowed caller should reach registry (404/405), got " + allowed.statusCode());
    }

    @Test
    void manifestReadDeniedWithoutPolicyAllow() throws Exception {
        String deniedUser = "ecr-registry-denied";
        CtfLabIamTestSupport.createUser(deniedUser);
        CtfLabIamTestSupport.putUserPolicy(deniedUser, "ecr-login", """
            {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ecr:GetAuthorizationToken","Resource":"*"}]}
            """);
        String deniedAkid = CtfLabIamTestSupport.createAccessKey(deniedUser);
        String deniedToken = fetchAuthToken(deniedAkid);
        String path = "/v2/" + REPO + "/manifests/missing-tag";
        HttpResponse<String> resp = httpGet(path, basicAuthFromToken(deniedToken));
        assertEquals(403, resp.statusCode(), resp.body());
    }

    private String fetchAuthToken(String accessKeyId) {
        return given()
                .header("X-Amz-Target", PREFIX + "GetAuthorizationToken")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(accessKeyId, "ecr"))
                .contentType(CT)
                .body("{}")
                .when().post("/")
                .then().statusCode(200)
                .extract().jsonPath().getString("authorizationData[0].authorizationToken");
    }

    private static String basicAuthFromToken(String authorizationToken) {
        String decoded = new String(Base64.getDecoder().decode(authorizationToken), StandardCharsets.UTF_8);
        return "Basic " + Base64.getEncoder().encodeToString(decoded.getBytes(StandardCharsets.UTF_8));
    }

    private HttpResponse<String> httpGet(String path, String authorization) throws Exception {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("http://localhost:" + registryPort + path))
                .timeout(java.time.Duration.ofSeconds(10))
                .GET();
        if (authorization != null) {
            builder.header("Authorization", authorization);
        }
        return HttpClient.newHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }
}
