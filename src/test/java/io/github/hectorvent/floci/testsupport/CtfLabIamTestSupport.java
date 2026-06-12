package io.github.hectorvent.floci.testsupport;

import io.github.hectorvent.floci.testing.RestAssuredJsonUtils;
import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;

import java.net.URL;

import static io.restassured.RestAssured.given;

/**
 * Shared IAM provisioning helpers for CTF lab integration tests.
 */
public final class CtfLabIamTestSupport {

    public static final String JSON_11 = "application/x-amz-json-1.1";
    public static final String CLOUDTRAIL_TARGET_PREFIX =
            "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.";
    public static final String CONFIG_TARGET_PREFIX = "StarlingDoveService.";
    public static final String GUARDDUTY_TARGET_PREFIX = "GuardDuty_2017-11-28.";
    public static final String SECURITY_HUB_TARGET_PREFIX = "AWSSecurityHub.";

    private CtfLabIamTestSupport() {}

    /** Binds RestAssured to the Quarkus test HTTP endpoint (required with {@code @TestProfile}). */
    public static void bindRestAssured(URL endpoint) {
        RestAssuredJsonUtils.configureAwsContentTypes();
        RestAssured.baseURI = endpoint.toString();
        RestAssured.port = endpoint.getPort();
    }

    public static String createUser(String userName) {
        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", userName)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
        return userName;
    }

    public static String createAccessKey(String userName) {
        return given()
                .formParam("Action", "CreateAccessKey")
                .formParam("UserName", userName)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200)
                .extract().xmlPath()
                .getString("CreateAccessKeyResponse.CreateAccessKeyResult.AccessKey.AccessKeyId");
    }

    public static void putUserPolicy(String userName, String policyName, String policyDocument) {
        given()
                .formParam("Action", "PutUserPolicy")
                .formParam("UserName", userName)
                .formParam("PolicyName", policyName)
                .formParam("PolicyDocument", policyDocument)
                .header("Authorization", CtfLabIamEnforcementProfile.AUTH)
                .when().post("/")
                .then().statusCode(200);
    }

    public static String playerAuth(String accessKeyId) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/s3/aws4_request";
    }

    public static String playerIamAuth(String accessKeyId) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/iam/aws4_request";
    }

    public static String playerStsAuth(String accessKeyId) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/sts/aws4_request";
    }

    public static String scopedAuth(String accessKeyId, String service) {
        return "AWS4-HMAC-SHA256 Credential=" + accessKeyId + "/20260227/us-east-1/" + service + "/aws4_request";
    }

    /** Creates an S3 bucket (no auth; use with IAM enforcement off). */
    public static void createBucket(String bucketName) {
        given()
        .when()
                .put("/" + bucketName)
        .then()
                .statusCode(200);
    }

    /** Uploads an object via S3 REST PUT (no auth). */
    public static void putObject(String bucket, String key, String body) {
        given()
                .contentType("text/plain")
                .body(body)
        .when()
                .put("/" + bucket + "/" + key)
        .then()
                .statusCode(200);
    }

    /** GET object body as string (no auth). */
    public static String getObject(String bucket, String key) {
        return given()
        .when()
                .get("/" + bucket + "/" + key)
        .then()
                .statusCode(200)
                .extract().asString();
    }

    /** Lists bucket keys via ListBucketResult XML (no auth). */
    public static ValidatableResponse listBucket(String bucket) {
        return given()
        .when()
                .get("/" + bucket)
        .then();
    }

    /** Installs a bucket policy JSON document. */
    public static void putBucketPolicy(String bucket, String policyJson) {
        given()
                .contentType("application/json")
                .body(policyJson)
        .when()
                .put("/" + bucket + "?policy")
        .then()
                .statusCode(200);
    }

    /** CloudTrail JSON 1.1 call without Authorization (forensic lab profile). */
    public static ValidatableResponse cloudTrail(String action, String jsonBody) {
        return given()
                .header("X-Amz-Target", CLOUDTRAIL_TARGET_PREFIX + action)
                .contentType(JSON_11)
                .body(jsonBody)
        .when()
                .post("/")
        .then();
    }

    /** AWS Config JSON 1.1 call without Authorization (forensic lab profile). */
    public static ValidatableResponse configService(String action, String jsonBody) {
        return given()
                .header("X-Amz-Target", CONFIG_TARGET_PREFIX + action)
                .contentType(JSON_11)
                .body(jsonBody)
        .when()
                .post("/")
        .then();
    }

    /** GuardDuty JSON 1.1 call without Authorization (forensic lab profile). */
    public static ValidatableResponse guardDuty(String action, String jsonBody) {
        return given()
                .header("X-Amz-Target", GUARDDUTY_TARGET_PREFIX + action)
                .contentType(JSON_11)
                .body(jsonBody)
        .when()
                .post("/")
        .then();
    }

    /** Security Hub JSON 1.1 call without Authorization (forensic lab profile). */
    public static ValidatableResponse securityHub(String action, String jsonBody) {
        return given()
                .header("X-Amz-Target", SECURITY_HUB_TARGET_PREFIX + action)
                .contentType(JSON_11)
                .body(jsonBody)
        .when()
                .post("/")
        .then();
    }

    /** IAM Query API call without Authorization (forensic lab profile). */
    public static ValidatableResponse iamQuery(String action) {
        return given()
                .formParam("Action", action)
                .formParam("Version", "2010-05-08")
        .when()
                .post("/")
        .then();
    }

    /** Creates an IAM user without Authorization (forensic lab profile). */
    public static void createIamUser(String userName) {
        given()
                .formParam("Action", "CreateUser")
                .formParam("UserName", userName)
                .formParam("Version", "2010-05-08")
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    /**
     * Bucket policy fragment allowing CloudTrail to write under {@code AWSLogs/}.
     */
    public static String cloudTrailBucketPolicy(String bucket, String trailName, String account, String region) {
        return """
                {"Version":"2012-10-17","Statement":[{"Sid":"AllowCloudTrail","Effect":"Allow",\
                "Principal":{"Service":"cloudtrail.amazonaws.com"},"Action":"s3:PutObject",\
                "Resource":"arn:aws:s3:::%s/AWSLogs/*","Condition":{"StringEquals":\
                {"aws:SourceArn":"arn:aws:cloudtrail:%s:%s:trail/%s"}}}]}\
                """.formatted(bucket, region, account, trailName);
    }
}
