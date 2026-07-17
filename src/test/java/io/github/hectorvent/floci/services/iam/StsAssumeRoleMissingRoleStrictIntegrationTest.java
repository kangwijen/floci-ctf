package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

/**
 * Under IAM enforcement plus strict mode, AssumeRole must not mint ASIA credentials
 * for a role that does not exist (no UnknownRole session).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@Tag("security-regression")
class StsAssumeRoleMissingRoleStrictIntegrationTest {

    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String MISSING_ROLE_ARN =
            "arn:aws:iam::" + ACCOUNT + ":role/does-not-exist-role";

    @TestHTTPResource("/")
    URL endpoint;

    @BeforeAll
    void bind() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
    }

    @Test
    void assumeRoleForMissingRoleIsDeniedUnderStrictIam() {
        given()
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(
                        CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "sts"))
                .formParam("Action", "AssumeRole")
                .formParam("RoleArn", MISSING_ROLE_ARN)
                .formParam("RoleSessionName", "missing-role-session")
                .when().post("/")
                .then()
                .statusCode(403)
                .body("ErrorResponse.Error.Code", equalTo("AccessDenied"));
    }
}
