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
 * Verifies that, with {@code iam.enforcement-enabled=true}, STS AssumeRole honors the target role's
 * trust policy: a caller the trust policy permits succeeds; one it does not is denied; and a role
 * Floci does not know about stays permissive (backward-compatible).
 *
 * <p>Uses registered IAM user keys (CTF enforcement rejects unregistered 12-digit account AKIDs).
 */
@QuarkusTest
@TestProfile(AssumeRoleTrustPolicyIntegrationTest.EnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AssumeRoleTrustPolicyIntegrationTest {

    public static class EnforcementProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.auth.validate-signatures", "false",
                    "floci.auth.root-access-key-id", CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                    "floci.auth.root-secret-access-key", CtfLabIamEnforcementProfile.ROOT_SECRET);
        }
    }

    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String OPERATOR_AUTH = CtfLabIamEnforcementProfile.AUTH;
    private static final String ASSUME_ANY = """
            {"Version":"2012-10-17","Statement":[{
              "Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}
            ]}""";

    @TestHTTPResource("/")
    URL endpoint;

    private String allowedUserKey;
    private String deniedUserKey;

    @BeforeAll
    void provisionUsers() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        CtfLabIamTestSupport.createUser("trust-allowed");
        allowedUserKey = CtfLabIamTestSupport.createAccessKey("trust-allowed");
        CtfLabIamTestSupport.putUserPolicy("trust-allowed", "assume-any-role", ASSUME_ANY);

        CtfLabIamTestSupport.createUser("trust-denied");
        deniedUserKey = CtfLabIamTestSupport.createAccessKey("trust-denied");
        CtfLabIamTestSupport.putUserPolicy("trust-denied", "assume-any-role", ASSUME_ANY);
    }

    private void createTrustedRole(String roleName) {
        String trustPolicy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Principal":{"AWS":"arn:aws:iam::%s:user/trust-allowed"},
                  "Action":"sts:AssumeRole"
                }]}""".formatted(ACCOUNT);

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "CreateRole")
                .formParam("RoleName", roleName)
                .formParam("AssumeRolePolicyDocument", trustPolicy)
                .header("Authorization", OPERATOR_AUTH)
                .when().post("/")
                .then().statusCode(200);
    }

    @Test
    void permittedCallerCanAssumeRole() {
        String role = "trust-ok-" + UUID.randomUUID().toString().substring(0, 8);
        createTrustedRole(role);

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/" + role)
                .formParam("RoleSessionName", "s")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(allowedUserKey))
                .when().post("/")
                .then().statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }

    @Test
    void unauthorizedCallerIsDenied() {
        String role = "trust-deny-" + UUID.randomUUID().toString().substring(0, 8);
        createTrustedRole(role);
        String roleArn = "arn:aws:iam::" + ACCOUNT + ":role/" + role;

        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "s")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(deniedUserKey))
                .when().post("/")
                .then().statusCode(403)
                .body(containsString("AccessDenied"))
                .body(containsString("User: "))
                .body(containsString("is not authorized to perform: sts:AssumeRole on resource: " + roleArn));
    }

    @Test
    void unknownRoleStaysPermissive() {
        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", "arn:aws:iam::" + ACCOUNT + ":role/never-created-"
                        + UUID.randomUUID().toString().substring(0, 8))
                .formParam("RoleSessionName", "s")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(deniedUserKey))
                .when().post("/")
                .then().statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }
}
