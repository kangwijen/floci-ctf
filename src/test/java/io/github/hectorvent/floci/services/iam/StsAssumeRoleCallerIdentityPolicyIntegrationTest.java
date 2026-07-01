package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.Map;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

/**
 * Same-account {@code sts:AssumeRole} caller identity policy: trust policy alone is sufficient
 * unless the caller has an explicit identity Deny on the role ARN.
 */
@QuarkusTest
@TestProfile(StsAssumeRoleCallerIdentityPolicyIntegrationTest.EnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class StsAssumeRoleCallerIdentityPolicyIntegrationTest {

    public static class EnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.strict-enforcement-enabled", "true",
                    "floci.auth.validate-signatures", "false",
                    "floci.auth.root-access-key-id", CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                    "floci.auth.root-secret-access-key", CtfLabIamEnforcementProfile.ROOT_SECRET);
        }
    }

    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;

    @TestHTTPResource("/")
    URL endpoint;

    private String trustedUserKey;
    private String deniedUserKey;
    private String wildcardDenyUserKey;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        CtfLabIamTestSupport.createUser("caller-trusted");
        trustedUserKey = CtfLabIamTestSupport.createAccessKey("caller-trusted");

        CtfLabIamTestSupport.createUser("caller-denied");
        deniedUserKey = CtfLabIamTestSupport.createAccessKey("caller-denied");
        CtfLabIamTestSupport.putUserPolicy("caller-denied", "deny-assume", """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}
                ]}""");

        CtfLabIamTestSupport.createUser("caller-wildcard-deny");
        wildcardDenyUserKey = CtfLabIamTestSupport.createAccessKey("caller-wildcard-deny");
    }

    @Test
    void sameAccountNoIdentityPolicySucceedsWhenTrustAllows() {
        String roleName = "caller-id-" + UUID.randomUUID().toString().substring(0, 8);
        String roleArn = createRoleTrustedFor("caller-trusted", roleName);

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "ok")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(trustedUserKey))
                .when().post("/")
                .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }

    @Test
    void sameAccountExplicitDenyBlocksEvenWhenTrusted() {
        String roleName = "caller-deny-" + UUID.randomUUID().toString().substring(0, 8);
        String roleArn = createRoleTrustedFor("caller-denied", roleName);

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "nope")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(deniedUserKey))
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }

    @Test
    void sameAccountDenyOnSpecificRoleArnBlocks() {
        String roleName = "caller-deny-arn-" + UUID.randomUUID().toString().substring(0, 8);
        String roleArn = createRoleTrustedFor("caller-wildcard-deny", roleName);
        CtfLabIamTestSupport.putUserPolicy("caller-wildcard-deny", "deny-this-role", """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Deny","Action":"sts:AssumeRole","Resource":"%s"}
                ]}""".formatted(roleArn));

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "nope")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(wildcardDenyUserKey))
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }

    private String createRoleTrustedFor(String userName, String roleName) {
        String trustPolicy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Principal":{"AWS":"arn:aws:iam::%s:user/%s"},
                  "Action":"sts:AssumeRole"
                }]}""".formatted(ACCOUNT, userName);

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", trustPolicy)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);

        return "arn:aws:iam::" + ACCOUNT + ":role/" + roleName;
    }
}
