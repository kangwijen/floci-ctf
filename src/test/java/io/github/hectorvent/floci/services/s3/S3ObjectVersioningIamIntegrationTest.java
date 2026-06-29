package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.testsupport.CtfLabIamEnforcementProfile;
import io.github.hectorvent.floci.testsupport.CtfLabIamTestSupport;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;

/**
 * S3 versioning IAM actions ({@code s3:ListBucketVersions}, {@code s3:GetObjectVersion}).
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class S3ObjectVersioningIamIntegrationTest {

    @TestHTTPResource("/")
    java.net.URL endpoint;

    private static final String BUCKET = "version-iam-bucket";
    private static final String ALLOWED_KEY = "versioned-object-key";
    private static final String OTHER_KEY = "other-key";

    private String playerAkid;
    private String playerAuth;
    private String allowedVersionId;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "s3-ver-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);
        playerAuth = CtfLabIamTestSupport.playerAuth(playerAkid);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":["s3:ListBucketVersions","s3:GetObjectVersion"],
               "Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/%s"]}
            ]}""".formatted(BUCKET, BUCKET, ALLOWED_KEY);
        CtfLabIamTestSupport.putUserPolicy(user, "version-read", policy);

        String rootS3 = CtfLabIamTestSupport.playerAuth(CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID);

        given().header("Authorization", rootS3).when().put("/" + BUCKET).then().statusCode(200);
        given()
                .header("Authorization", rootS3)
                .body("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
                .when().put("/" + BUCKET + "?versioning")
                .then().statusCode(200);

        given().header("Authorization", rootS3).body("forged-body").when().put("/" + BUCKET + "/" + ALLOWED_KEY)
                .then().statusCode(200);
        allowedVersionId = given()
                .header("Authorization", rootS3)
                .body("version-one-value")
                .when().put("/" + BUCKET + "/" + ALLOWED_KEY)
                .then().statusCode(200)
                .extract().header("x-amz-version-id");

        given().header("Authorization", rootS3).body("other-object").when().put("/" + BUCKET + "/" + OTHER_KEY)
                .then().statusCode(200);
    }

    @Test
    void listVersionsAllowedForAllowedPrefix() {
        given()
                .header("Authorization", playerAuth)
                .queryParam("versions", "")
                .queryParam("prefix", ALLOWED_KEY)
                .when().get("/" + BUCKET)
                .then().statusCode(200)
                .body(containsString(ALLOWED_KEY));
    }

    @Test
    void getAllowedObjectVersionAllowed() {
        given()
                .header("Authorization", playerAuth)
                .queryParam("versionId", allowedVersionId)
                .when().get("/" + BUCKET + "/" + ALLOWED_KEY)
                .then().statusCode(200)
                .body(containsString("version-one-value"));
    }

    @Test
    void listVersionsDeniedWhenPrefixConditionNotMet() {
        String prefixUser = "s3-ver-prefix";
        CtfLabIamTestSupport.createUser(prefixUser);
        String prefixAkid = CtfLabIamTestSupport.createAccessKey(prefixUser);
        String prefixAuth = CtfLabIamTestSupport.playerAuth(prefixAkid);

        String prefixPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucketVersions","Resource":"arn:aws:s3:::%s",
               "Condition":{"StringLike":{"s3:prefix":["%s*"]}}}
            ]}""".formatted(BUCKET, ALLOWED_KEY);
        CtfLabIamTestSupport.putUserPolicy(prefixUser, "prefix-list", prefixPolicy);

        given()
                .header("Authorization", prefixAuth)
                .queryParam("versions", "")
                .queryParam("prefix", OTHER_KEY)
                .when().get("/" + BUCKET)
                .then().statusCode(403);
    }

    @Test
    void listVersionsAllowedWhenPrefixConditionMatches() {
        String prefixUser = "s3-ver-prefix-ok";
        CtfLabIamTestSupport.createUser(prefixUser);
        String prefixAkid = CtfLabIamTestSupport.createAccessKey(prefixUser);
        String prefixAuth = CtfLabIamTestSupport.playerAuth(prefixAkid);

        String prefixPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"s3:ListBucketVersions","Resource":"arn:aws:s3:::%s",
               "Condition":{"StringLike":{"s3:prefix":["%s*"]}}}
            ]}""".formatted(BUCKET, ALLOWED_KEY);
        CtfLabIamTestSupport.putUserPolicy(prefixUser, "prefix-list-ok", prefixPolicy);

        given()
                .header("Authorization", prefixAuth)
                .queryParam("versions", "")
                .queryParam("prefix", ALLOWED_KEY)
                .when().get("/" + BUCKET)
                .then().statusCode(200)
                .body(containsString(ALLOWED_KEY));
    }

    @Test
    void getOtherObjectVersionDenied() {
        given()
                .header("Authorization", playerAuth)
                .when().get("/" + BUCKET + "/" + OTHER_KEY)
                .then().statusCode(403);
    }

    @Test
    void listVersionsShowsAllowedNotOtherWhenPrefixScoped() {
        given()
                .header("Authorization", playerAuth)
                .queryParam("versions", "")
                .queryParam("prefix", ALLOWED_KEY)
                .when().get("/" + BUCKET)
                .then().statusCode(200)
                .body(not(containsString(OTHER_KEY)));
    }
}
