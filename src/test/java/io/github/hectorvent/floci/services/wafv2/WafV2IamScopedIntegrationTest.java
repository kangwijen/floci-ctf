package io.github.hectorvent.floci.services.wafv2;

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
 * {@code wafv2:GetWebACL} scoped to one Web ACL ARN pattern.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WafV2IamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "AWSWAF_20190729.";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedAclId;
    private String decoyAclId;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-waf-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "wafv2");

        allowedAclId = createWebAcl(rootAuth, "ctf-allowed-acl");
        decoyAclId = createWebAcl(rootAuth, "ctf-decoy-acl");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"wafv2:GetWebACL",
               "Resource":"arn:aws:wafv2:%s:%s:regional/webacl/ctf-allowed-acl/*"}
            ]}""".formatted(REGION, ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "get-one-acl", policy);
    }

    @Test
    void getAllowedWebAcl() {
        given()
                .header("Authorization", playerWafAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "GetWebACL")
                .contentType(CT)
                .body("{\"Scope\":\"REGIONAL\",\"Id\":\"" + allowedAclId + "\",\"Name\":\"ctf-allowed-acl\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("WebACL.Name", equalTo("ctf-allowed-acl"));
    }

    @Test
    void getDecoyWebAclDenied() {
        given()
                .header("Authorization", playerWafAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "GetWebACL")
                .contentType(CT)
                .body("{\"Scope\":\"REGIONAL\",\"Id\":\"" + decoyAclId + "\",\"Name\":\"ctf-decoy-acl\"}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static String createWebAcl(String auth, String name) {
        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "CreateWebACL")
                .contentType(CT)
                .body("""
                        {"Name":"%s","Scope":"REGIONAL","DefaultAction":{"Allow":{}},"VisibilityConfig":{
                          "SampledRequestsEnabled":true,"CloudWatchMetricsEnabled":true,"MetricName":"%s"}}
                        """.formatted(name, name))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Summary.Id", notNullValue())
                .extract().jsonPath().getString("Summary.Id");
    }

    private String playerWafAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "wafv2");
    }
}
