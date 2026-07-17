package io.github.hectorvent.floci.services.resourcegroupstagging;

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
import static org.hamcrest.Matchers.anEmptyMap;
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code tagging:TagResources} scoped to one S3 bucket ARN in {@code ResourceARNList}.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TaggingIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "ResourceGroupsTaggingAPI_20170126.";
    private static final String ALLOWED_BUCKET = "tagging-allowed-bucket";
    private static final String DECOY_BUCKET = "tagging-other-bucket";
    private static final String ALLOWED_ARN = "arn:aws:s3:::" + ALLOWED_BUCKET;
    private static final String DECOY_ARN = "arn:aws:s3:::" + DECOY_BUCKET;

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "tagging-test-user";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootS3 = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "s3");
        given().header("Authorization", rootS3).when().put("/" + ALLOWED_BUCKET).then().statusCode(200);
        given().header("Authorization", rootS3).when().put("/" + DECOY_BUCKET).then().statusCode(200);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"tagging:TagResources",
               "Resource":"%s"}
            ]}""".formatted(ALLOWED_ARN);
        CtfLabIamTestSupport.putUserPolicy(user, "tag-one-bucket", policy);
    }

    @Test
    void tagAllowedBucket() {
        given()
                .header("Authorization", playerTaggingAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "TagResources")
                .contentType(CT)
                .body("""
                        {
                          "ResourceARNList": ["%s"],
                          "Tags": {"Environment": "allowed"}
                        }
                        """.formatted(ALLOWED_ARN))
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("FailedResourcesMap", anEmptyMap());
    }

    @Test
    void tagDecoyBucketDenied() {
        given()
                .header("Authorization", playerTaggingAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "TagResources")
                .contentType(CT)
                .body("""
                        {
                          "ResourceARNList": ["%s"],
                          "Tags": {"Environment": "decoy"}
                        }
                        """.formatted(DECOY_ARN))
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    /**
     * Multi-entry {@code ResourceARNList} with no ARN-prefixed entries must still be evaluated
     * against IAM (as the {@code *} resource) rather than skipped entirely. A caller with no
     * {@code tagging:TagResources} Allow policy must be denied, not silently let through.
     */
    @Test
    void tagResourcesWithNonArnListDeniedNotBypassed() {
        given()
                .header("Authorization", playerTaggingAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "TagResources")
                .contentType(CT)
                .body("""
                        {
                          "ResourceARNList": ["not-an-arn-1", "not-an-arn-2"],
                          "Tags": {"Environment": "bypass-attempt"}
                        }
                        """)
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private String playerTaggingAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "tagging");
    }
}
