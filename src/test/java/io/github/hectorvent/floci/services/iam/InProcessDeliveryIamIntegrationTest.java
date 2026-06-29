package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * IAM enforcement on in-process S3 notification and service delivery paths.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class InProcessDeliveryIamIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String BUCKET = "inprocess-delivery-bucket";
    private static final String LAMBDA_ARN =
            "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:s3-no-policy";

    @TestHTTPResource("/")
    URL endpoint;

    @Inject
    InProcessTargetAuthorizer targetAuthorizer;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);

        String rootAuth = CtfLabIamTestSupport.playerAuth(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID);
        given().header("Authorization", rootAuth).when().put("/" + BUCKET).then().statusCode(200);
    }

    @Test
    void s3ToLambdaDeniesWithoutLambdaResourcePolicy() {
        AwsException ex = assertThrows(AwsException.class,
                () -> targetAuthorizer.authorizeS3ToLambda(LAMBDA_ARN, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void cloudTrailS3PutDeniesWithoutBucketPolicy() {
        AwsException ex = assertThrows(AwsException.class, () -> targetAuthorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE, BUCKET, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }
}
