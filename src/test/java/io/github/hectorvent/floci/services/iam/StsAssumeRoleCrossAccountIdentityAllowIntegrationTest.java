package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.arc.Arc;
import io.quarkus.arc.ManagedContext;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;

/**
 * Cross-account {@code sts:AssumeRole} under CTF IAM enforcement requires caller identity
 * Allow on the foreign role ARN in addition to trust policy Allow (AWS-shaped).
 *
 * <p>Same-account trust-only behavior is covered by
 * {@link StsAssumeRoleCallerIdentityPolicyIntegrationTest}. This class covers the
 * {@code validateCallerIdentityForAssumeRole} cross-account branch.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class StsAssumeRoleCrossAccountIdentityAllowIntegrationTest {

    private static final String CALLER_ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String ROLE_ACCOUNT = "222233334444";
    private static final String CALLER_USER = "cross-acct-assume-caller";
    private static final String ALLOWED_USER = "cross-acct-assume-allowed";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    IamService iamService;

    private String callerKey;
    private String allowedKey;
    private String roleArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        CtfLabIamTestSupport.createUser(CALLER_USER);
        callerKey = CtfLabIamTestSupport.createAccessKey(CALLER_USER);

        CtfLabIamTestSupport.createUser(ALLOWED_USER);
        allowedKey = CtfLabIamTestSupport.createAccessKey(ALLOWED_USER);

        String roleName = "cross-acct-" + UUID.randomUUID().toString().substring(0, 8);
        roleArn = "arn:aws:iam::" + ROLE_ACCOUNT + ":role/" + roleName;
        String trustPolicy = """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow",
                  "Principal":{"AWS":[
                    "arn:aws:iam::%s:user/%s",
                    "arn:aws:iam::%s:user/%s"
                  ]},
                  "Action":"sts:AssumeRole"
                }]}""".formatted(CALLER_ACCOUNT, CALLER_USER, CALLER_ACCOUNT, ALLOWED_USER);

        seedRoleInAccount(ROLE_ACCOUNT, roleName, trustPolicy);

        CtfLabIamTestSupport.putUserPolicy(ALLOWED_USER, "allow-cross-assume", """
                {"Version":"2012-10-17","Statement":[{
                  "Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"
                }]}""".formatted(roleArn));
    }

    @Test
    void crossAccountTrustAloneWithoutIdentityAllowIsDenied() {
        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "no-identity-allow")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(callerKey))
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("AccessDenied"));
    }

    @Test
    void crossAccountTrustPlusIdentityAllowSucceeds() {
        given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", roleArn)
                .formParam("RoleSessionName", "with-identity-allow")
                .header("Authorization", CtfLabIamTestSupport.playerStsAuth(allowedKey))
                .when().post("/")
                .then()
                .statusCode(200)
                .body("AssumeRoleResponse.AssumeRoleResult.Credentials.AccessKeyId", startsWith("ASIA"));
    }

    private void seedRoleInAccount(String accountId, String roleName, String trustPolicy) {
        ManagedContext requestContext = Arc.container().requestContext();
        boolean wasActive = requestContext.isActive();
        if (!wasActive) {
            requestContext.activate();
        }
        try {
            RequestContext ctx = Arc.container().instance(RequestContext.class).get();
            ctx.setAccountId(accountId);
            iamService.createRole(roleName, "/", trustPolicy, "cross-account assume regression", 3600, null);
        } finally {
            if (!wasActive) {
                requestContext.terminate();
            }
        }
    }
}
