package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

/**
 * {@code x-amz-bypass-governance-retention:true} must require {@code s3:BypassGovernanceRetention}
 * on the caller's identity, independent of the underlying {@code s3:DeleteObject} /
 * {@code s3:PutObjectRetention} permission. Before this fix, any caller who could delete an
 * object or update its retention could always set the bypass header to override an active
 * GOVERNANCE-mode Object Lock, defeating the point of that lock as a separately privileged
 * control.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class S3BypassGovernanceRetentionIamIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String BUCKET = "bypass-gov-bucket";
    private String rootAuth;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        rootAuth = CtfLabIamTestSupport.playerAuth(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID);

        given()
                .header("Authorization", rootAuth)
                .header("x-amz-bucket-object-lock-enabled", "true")
                .when().put("/" + BUCKET)
                .then().statusCode(200);
    }

    private String futureRetainUntil() {
        return Instant.now().plus(1, ChronoUnit.DAYS).toString();
    }

    private void putLockedObject(String key, String body) {
        given()
                .header("Authorization", rootAuth)
                .header("x-amz-object-lock-mode", "GOVERNANCE")
                .header("x-amz-object-lock-retain-until-date", futureRetainUntil())
                .body(body)
                .when().put("/" + BUCKET + "/" + key)
                .then().statusCode(200);
    }

    private String createPlayer(String userName, String policyDocument) {
        CtfLabIamTestSupport.createUser(userName);
        String akid = CtfLabIamTestSupport.createAccessKey(userName);
        CtfLabIamTestSupport.putUserPolicy(userName, userName + "-policy", policyDocument);
        return CtfLabIamTestSupport.playerAuth(akid);
    }

    @Test
    void deleteWithBypassHeaderDeniedWithoutBypassGovernanceRetentionPermission() {
        String key = "delete-deny-key";
        putLockedObject(key, "locked-body");

        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::%s/%s"}
                ]}""".formatted(BUCKET, key);
        String playerAuth = createPlayer("bypass-deny-deleter", policy);

        given()
                .header("Authorization", playerAuth)
                .header("x-amz-bypass-governance-retention", "true")
                .when().delete("/" + BUCKET + "/" + key)
                .then()
                .statusCode(403)
                .body(containsString("AccessDeniedException"));
    }

    @Test
    void deleteWithBypassHeaderAllowedWithBypassGovernanceRetentionPermission() {
        String key = "delete-allow-key";
        putLockedObject(key, "locked-body");

        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":["s3:DeleteObject","s3:BypassGovernanceRetention"],
                   "Resource":"arn:aws:s3:::%s/%s"}
                ]}""".formatted(BUCKET, key);
        String playerAuth = createPlayer("bypass-allow-deleter", policy);

        given()
                .header("Authorization", playerAuth)
                .header("x-amz-bypass-governance-retention", "true")
                .when().delete("/" + BUCKET + "/" + key)
                .then()
                .statusCode(204);
    }

    @Test
    void deleteWithoutBypassHeaderNeedsNoBypassGovernanceRetentionPermissionButStillBlockedByLock() {
        String key = "delete-no-bypass-key";
        putLockedObject(key, "locked-body");

        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::%s/%s"}
                ]}""".formatted(BUCKET, key);
        String playerAuth = createPlayer("no-bypass-deleter", policy);

        given()
                .header("Authorization", playerAuth)
                .when().delete("/" + BUCKET + "/" + key)
                .then()
                .statusCode(403)
                .body(containsString("GOVERNANCE"));
    }

    @Test
    void putObjectRetentionWithBypassHeaderDeniedWithoutBypassGovernanceRetentionPermission() {
        String key = "retention-deny-key";
        putLockedObject(key, "locked-body");

        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"s3:PutObjectRetention","Resource":"arn:aws:s3:::%s/%s"}
                ]}""".formatted(BUCKET, key);
        String playerAuth = createPlayer("retention-deny-player", policy);

        String retentionBody = """
                <Retention>
                  <Mode>GOVERNANCE</Mode>
                  <RetainUntilDate>%s</RetainUntilDate>
                </Retention>""".formatted(futureRetainUntil());

        given()
                .header("Authorization", playerAuth)
                .header("x-amz-bypass-governance-retention", "true")
                .body(retentionBody)
                .when().put("/" + BUCKET + "/" + key + "?retention")
                .then()
                .statusCode(403)
                .body(containsString("AccessDeniedException"));
    }

    @Test
    void putObjectRetentionWithBypassHeaderAllowedWithBypassGovernanceRetentionPermission() {
        String key = "retention-allow-key";
        putLockedObject(key, "locked-body");

        String policy = """
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":["s3:PutObjectRetention","s3:BypassGovernanceRetention"],
                   "Resource":"arn:aws:s3:::%s/%s"}
                ]}""".formatted(BUCKET, key);
        String playerAuth = createPlayer("retention-allow-player", policy);

        String retentionBody = """
                <Retention>
                  <Mode>GOVERNANCE</Mode>
                  <RetainUntilDate>%s</RetainUntilDate>
                </Retention>""".formatted(futureRetainUntil());

        given()
                .header("Authorization", playerAuth)
                .header("x-amz-bypass-governance-retention", "true")
                .body(retentionBody)
                .when().put("/" + BUCKET + "/" + key + "?retention")
                .then()
                .statusCode(200);
    }
}
