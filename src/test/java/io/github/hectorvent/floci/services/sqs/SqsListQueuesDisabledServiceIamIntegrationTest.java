package io.github.hectorvent.floci.services.sqs;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.junit.QuarkusTestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * When {@code floci.services.sqs.enabled=false}, authenticated players lacking
 * {@code sqs:ListQueues} must get IAM {@code AccessDenied}, not
 * {@code ServiceNotAvailableException} from {@link io.github.hectorvent.floci.core.common.ServiceEnabledFilter}.
 */
@QuarkusTest
@TestProfile(SqsListQueuesDisabledServiceIamIntegrationTest.DisabledSqsIamProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SqsListQueuesDisabledServiceIamIntegrationTest {

    private static final String REGION = "us-east-1";

    @TestHTTPResource("/")
    URL endpoint;

    @BeforeAll
    void bind() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
    }

    @Test
    void listQueuesDeniedWhenSqsDisabledInConfigReturnsAccessDenied() {
        String user = "sqs-disabled-list-test-user";
        CtfLabIamTestSupport.createUser(user);
        String akid = CtfLabIamTestSupport.createAccessKey(user);
        String receiveOnlyPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"sqs:ReceiveMessage",
               "Resource":"arn:aws:sqs:%s:%s:some-queue"}
            ]}""".formatted(REGION, CtfLabIamEnforcementProfile.ACCOUNT);
        CtfLabIamTestSupport.putUserPolicy(user, "sqs-receive-only-disabled-svc", receiveOnlyPolicy);

        given()
                .formParam("Action", "ListQueues")
                .header("Authorization", CtfLabIamTestSupport.scopedAuth(akid, "sqs"))
                .contentType("application/x-www-form-urlencoded")
                .when().post("/")
                .then()
                .statusCode(403)
                .body(containsString("<Code>AccessDenied</Code>"))
                .body(not(containsString("ServiceNotAvailableException")));
    }

    public static final class DisabledSqsIamProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "floci.services.sqs.enabled", "false",
                    "floci.services.iam.enforcement-enabled", "true",
                    "floci.services.iam.strict-enforcement-enabled", "true",
                    "floci.auth.validate-signatures", "false",
                    "floci.auth.root-access-key-id", CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID,
                    "floci.auth.root-secret-access-key", CtfLabIamEnforcementProfile.ROOT_SECRET);
        }
    }
}
