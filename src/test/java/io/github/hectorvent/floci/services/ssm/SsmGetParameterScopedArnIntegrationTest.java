package io.github.hectorvent.floci.services.ssm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code ssm:GetParameter} scoped to one parameter ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SsmGetParameterScopedArnIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    @Inject
    ObjectMapper objectMapper;

    private String playerAkid;
    private static final String ALLOWED = "/test/scoped/external-id";
    private static final String DECOY = "/test/scoped/other-param";

    @BeforeAll
    void provision() throws Exception {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ssm-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = "AWS4-HMAC-SHA256 Credential=" + CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID
                + "/20260227/us-east-1/ssm/aws4_request";

        putParameter(rootAuth, ALLOWED, "trusted-id-value");
        putParameter(rootAuth, DECOY, "other-value");

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"ssm:GetParameter",
               "Resource":"arn:aws:ssm:us-east-1:%s:parameter/test/scoped/external-id"}
            ]}""".formatted(CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "ssm-read-one", policy);
    }

    private void putParameter(String auth, String name, String value) throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("Name", name);
        req.put("Value", value);
        req.put("Type", "String");
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", "AmazonSSM.PutParameter")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void getAllowedParameter() throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("Name", ALLOWED);
        given()
                .header("Authorization", playerSsmAuth())
                .header("X-Amz-Target", "AmazonSSM.GetParameter")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(200)
                .body("Parameter.Value", equalTo("trusted-id-value"));
    }

    @Test
    void getDecoyParameterDenied() throws Exception {
        ObjectNode req = objectMapper.createObjectNode();
        req.put("Name", DECOY);
        given()
                .header("Authorization", playerSsmAuth())
                .header("X-Amz-Target", "AmazonSSM.GetParameter")
                .contentType("application/x-amz-json-1.1")
                .body(req.toString())
                .when().post("/")
                .then().statusCode(403);
    }

    private String playerSsmAuth() {
        return "AWS4-HMAC-SHA256 Credential=" + playerAkid + "/20260227/us-east-1/ssm/aws4_request";
    }
}
