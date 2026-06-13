package io.github.hectorvent.floci.services.transcribe;

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
import static org.hamcrest.Matchers.equalTo;

/**
 * {@code transcribe:GetTranscriptionJob} scoped to one transcription job name.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class TranscribeIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "Transcribe.";
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = CtfLabIamEnforcementProfile.ACCOUNT;
    private static final String ALLOWED_JOB = "ctf-allowed-transcribe-job";
    private static final String DECOY_JOB = "ctf-decoy-transcribe-job";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "ctf-transcribe-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "transcribe");

        startTranscriptionJob(rootAuth, ALLOWED_JOB);
        startTranscriptionJob(rootAuth, DECOY_JOB);

        String allowedArn = "arn:aws:transcribe:" + REGION + ":" + ACCOUNT
                + ":transcription-job/" + ALLOWED_JOB;
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"transcribe:GetTranscriptionJob",
               "Resource":"%s"}
            ]}""".formatted(allowedArn);
        CtfLabIamTestSupport.putUserPolicy(user, "get-one-job", policy);
    }

    @Test
    void getAllowedTranscriptionJob() {
        given()
                .header("Authorization", playerTranscribeAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "GetTranscriptionJob")
                .contentType(CT)
                .body("{\"TranscriptionJobName\":\"" + ALLOWED_JOB + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("TranscriptionJob.TranscriptionJobName", equalTo(ALLOWED_JOB));
    }

    @Test
    void getDecoyTranscriptionJobDenied() {
        given()
                .header("Authorization", playerTranscribeAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "GetTranscriptionJob")
                .contentType(CT)
                .body("{\"TranscriptionJobName\":\"" + DECOY_JOB + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static void startTranscriptionJob(String auth, String jobName) {
        given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "StartTranscriptionJob")
                .contentType(CT)
                .body("""
                        {"TranscriptionJobName":"%s",
                         "Media":{"MediaFileUri":"s3://ctf-bucket/audio.wav"},
                         "LanguageCode":"en-US"}
                        """.formatted(jobName))
        .when()
                .post("/")
        .then()
                .statusCode(200);
    }

    private String playerTranscribeAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "transcribe");
    }
}
