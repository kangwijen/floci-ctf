package io.github.hectorvent.floci.services.acm;

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
import static org.hamcrest.Matchers.startsWith;

/**
 * {@code acm:DescribeCertificate} scoped to one certificate ARN.
 */
@QuarkusTest
@TestProfile(CtfLabIamEnforcementProfile.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AcmIamScopedIntegrationTest {

    private static final String CT = CtfLabIamTestSupport.JSON_11;
    private static final String TARGET_PREFIX = "CertificateManager.";
    private static final String ALLOWED_DOMAIN = "allowed.example.com";
    private static final String DECOY_DOMAIN = "other.example.com";

    @TestHTTPResource("/")
    URL endpoint;

    private String playerAkid;
    private String allowedCertificateArn;
    private String decoyCertificateArn;

    @BeforeAll
    void provision() {
        CtfLabIamTestSupport.bindRestAssured(endpoint);
        String user = "acm-player";
        CtfLabIamTestSupport.createUser(user);
        playerAkid = CtfLabIamTestSupport.createAccessKey(user);

        String rootAuth = CtfLabIamTestSupport.scopedAuth(
                CtfLabIamEnforcementProfile.ROOT_ACCESS_KEY_ID, "acm");

        allowedCertificateArn = requestCertificate(rootAuth, ALLOWED_DOMAIN);
        decoyCertificateArn = requestCertificate(rootAuth, DECOY_DOMAIN);

        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"acm:DescribeCertificate",
               "Resource":"%s"}
            ]}""".formatted(allowedCertificateArn);
        CtfLabIamTestSupport.putUserPolicy(user, "describe-one-certificate", policy);
    }

    @Test
    void describeAllowedCertificate() {
        given()
                .header("Authorization", playerAcmAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeCertificate")
                .contentType(CT)
                .body("{\"CertificateArn\":\"" + allowedCertificateArn + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("Certificate.CertificateArn", equalTo(allowedCertificateArn))
                .body("Certificate.DomainName", equalTo(ALLOWED_DOMAIN));
    }

    @Test
    void describeDecoyCertificateDenied() {
        given()
                .header("Authorization", playerAcmAuth())
                .header("X-Amz-Target", TARGET_PREFIX + "DescribeCertificate")
                .contentType(CT)
                .body("{\"CertificateArn\":\"" + decoyCertificateArn + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(403)
                .body("__type", equalTo("AccessDeniedException"));
    }

    private static String requestCertificate(String auth, String domainName) {
        return given()
                .header("Authorization", auth)
                .header("X-Amz-Target", TARGET_PREFIX + "RequestCertificate")
                .contentType(CT)
                .body("{\"DomainName\":\"" + domainName + "\"}")
        .when()
                .post("/")
        .then()
                .statusCode(200)
                .body("CertificateArn", startsWith("arn:aws:acm:"))
                .extract().jsonPath().getString("CertificateArn");
    }

    private String playerAcmAuth() {
        return CtfLabIamTestSupport.scopedAuth(playerAkid, "acm");
    }
}
