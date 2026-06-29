package io.github.hectorvent.floci.services.emr;

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
 * {@code elasticmapreduce:DescribeCluster} scoped to one cluster ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EmrIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "ElasticMapReduce.";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedClusterId;
    private String decoyClusterId;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "emr-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "elasticmapreduce");

        allowedClusterId = runJobFlow(rootAuth, "allowed-emr");
        decoyClusterId = runJobFlow(rootAuth, "other-emr");

        String allowedArn = "arn:aws:elasticmapreduce:" + REGION + ":" + ACCOUNT + ":cluster/" + allowedClusterId;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"elasticmapreduce:DescribeCluster",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "describe-one-cluster", policy);
    }

    @Test
    void describeAllowedCluster() {
        given()
                .header("Authorization", playerEmrAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeCluster")
                .contentType(CT)
                .body("{\"ClusterId\":\"" + allowedClusterId + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Cluster.Id", equalTo(allowedClusterId));
    }

    @Test
    void describeDecoyClusterDenied() {
        given()
                .header("Authorization", playerEmrAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeCluster")
                .contentType(CT)
                .body("{\"ClusterId\":\"" + decoyClusterId + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static String runJobFlow(String auth, String name) {
        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "RunJobFlow")
                .contentType(CT)
                .body("""
                        {"Name":"%s","ReleaseLabel":"emr-7.5.0",
                         "Instances":{"KeepJobFlowAliveWhenNoSteps":true,
                         "InstanceGroups":[{"Name":"master","InstanceRole":"MASTER",
                         "InstanceType":"m5.xlarge","InstanceCount":1}]}}
                        """.formatted(name))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("JobFlowId", startsWith("j-"))
                .extract().jsonPath().getString("JobFlowId");
    }

    private String playerEmrAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "elasticmapreduce");
    }
}
